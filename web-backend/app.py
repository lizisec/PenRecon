"""
PenRecon - 渗透测试自动化平台后端API

这个文件实现了PenRecon平台的后端API服务，主要功能包括：
1. AutoRecon扫描管理 - 启动、监控、获取扫描结果
2. 扫描结果解析 - 解析Nmap和漏洞扫描结果
3. 网络拓扑图生成 - 将扫描结果转换为可视化数据
4. AI分析集成 - 使用DeepSeek AI分析扫描结果
5. 文件上传处理 - 支持压缩文件上传和解压
6. 扫描状态管理 - 跟踪和管理扫描进度

作者: PenRecon Team
版本: 1.0.0
"""

# 标准库导入
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import shutil
from pathlib import Path
import networkx as nx
from typing import Dict, List, Optional
import logging
from datetime import datetime
import aiofiles
import json
import re  # 用于正则表达式匹配
from pydantic import BaseModel  # 数据验证模型
import subprocess
import asyncio
import uuid
from threading import Thread
import queue
import xml.etree.ElementTree as ET  # XML解析
from openai import OpenAI
from dotenv import load_dotenv
import httpx  # HTTP客户端
import zipfile  # ZIP文件处理
import tarfile  # TAR文件处理
import time
import select

# 加载环境变量（从.env文件）
load_dotenv()

# ============================================================================
# Pydantic 数据模型定义
# ============================================================================

class AnnotationRequest(BaseModel):
    """注释请求数据模型"""
    analysis_id: str  # 分析ID
    parent_node_name: str  # 父节点名称
    annotation_text: str  # 注释文本内容

class DeleteNodeRequest(BaseModel):
    """删除节点请求数据模型"""
    analysis_id: str  # 分析ID
    node_name: str  # 要删除的节点名称

class ScanRequest(BaseModel):
    """扫描请求数据模型"""
    ip: str  # 目标IP地址
    overwrite: bool = False  # 是否覆盖现有结果

# ============================================================================
# 日志配置
# ============================================================================

# 配置日志格式和级别
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# FastAPI 应用初始化
# ============================================================================

app = FastAPI(
    title="PenRecon API",
    description="渗透测试自动化平台后端API",
    version="1.0.0"
)

# 配置CORS中间件，允许前端跨域访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],  # 允许的前端域名
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有HTTP方法
    allow_headers=["*"],  # 允许所有请求头
)

# ============================================================================
# 健康检查端点
# ============================================================================

@app.get("/ping")
async def ping():
    """健康检查端点，用于测试API服务是否正常运行"""
    return {"message": "pong"}

# ============================================================================
# AI分析器类
# ============================================================================

class AutoReconAnalyzer:
    """
    AutoRecon结果AI分析器
    
    使用DeepSeek AI对AutoRecon扫描结果进行智能分析，
    生成渗透测试建议和攻击路径。
    """
    
    def __init__(self):
        """初始化AI分析器"""
        # 从环境变量获取API密钥
        api_key = os.getenv('DEEPSEEK_API_KEY')
        if not api_key:
            logger.error("DEEPSEEK_API_KEY environment variable not found. AI analysis will not be available.")
            self.client = None
            return
        
        logger.info("DEEPSEEK_API_KEY loaded successfully. Initializing DeepSeek AI client.")
        
        # 初始化OpenAI客户端（使用DeepSeek API）
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com/v1",
            http_client=httpx.Client()  # 显式设置无代理
        )
        logger.info("DeepSeek AI client initialized.")
        
    def read_results(self, results_path):
        """
        读取AutoRecon的结果文件
        
        Args:
            results_path (str): AutoRecon结果目录路径
            
        Returns:
            List[Dict]: 包含文件路径和内容的列表，如果失败返回None
        """
        logger.info(f"Attempting to read AutoRecon results from: {results_path}")
        results = []
        path = Path(results_path)
        
        if not path.exists():
            logger.error(f"错误: 指定的AutoRecon结果路径不存在: {results_path}")
            return None
            
        # 递归遍历所有文本文件
        for file_path in path.rglob("*.txt"):  # 只处理.txt文件进行分析
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():  # 只添加非空文件
                        results.append({
                            "file": str(file_path.relative_to(path)),  # 存储相对路径
                            "content": content
                        })
                        logger.debug(f"Successfully read file: {file_path}")
            except Exception as e:
                logger.warning(f"警告: 无法读取文件 {file_path}: {str(e)}")
                
        logger.info(f"Finished reading results. Found {len(results)} valid text files.")
        return results

    def analyze_results(self, results):
        """
        使用AI分析AutoRecon的结果
        
        Args:
            results (List[Dict]): 扫描结果列表
            
        Returns:
            str: AI分析报告，如果失败返回错误信息
        """
        logger.info("Starting AI analysis...")
        if not self.client:
            logger.error("AI analysis client is not initialized. Cannot proceed with analysis.")
            return "AI分析服务未初始化，因为缺少API密钥。"

        if not results:
            logger.warning("No results provided for AI analysis.")
            return "没有找到可分析的结果。"
            
        # 升级后的AI分析提示，参考hacktricks，增加更多工具和利用方式
        prompt = '''你是一位经验丰富的渗透测试专家。你收到了一份 AutoRecon 的扫描结果报告（包含 Nmap 扫描、漏洞扫描、开放端口信息等）。请根据这些结果，生成一份详细的渗透测试命令清单，列出下一步可能采取的攻击或信息收集命令。请将命令分为以下几个类别，并尽量覆盖常见的渗透测试工具和技巧（可参考 hacktricks 网站）：

**1. 信息收集与侦察 (Reconnaissance)**
*   **主机发现与端口扫描**：如 nmap、masscan、rustscan、amap、netcat、powershell 等。
*   **子域名与DNS信息枚举**：如 nslookup、dig、dnsenum、dnsrecon、amass、subfinder、assetfinder、ffuf、gobuster、wfuzz、crt.sh、Shodan、Censys、FOFA、hunter.io。
*   **Web目录/文件/参数爆破**：如 gobuster、ffuf、dirsearch、feroxbuster、wfuzz、arjun。
*   **SMB/NetBIOS/LDAP/AD信息收集**：如 enum4linux、smbmap、crackmapexec、rpcclient、nbtscan、ldapsearch、bloodhound、SharpHound、impacket 工具集。
*   **SNMP信息收集**：如 onesixtyone、snmpwalk、snmp-check。
*   **网络流量分析**：如 tcpdump、wireshark、tshark、mitmproxy、bettercap、responder。
*   **被动信息收集**：如 Wappalyzer、BuiltWith、Shodan、Censys、FOFA、Google Dorking。
*   **云服务与资产收集**：如 cloud_enum、S3Scanner、ScoutSuite、Pacu。

**2. 域渗透初步信息收集 (Active Directory Recon)**
*   **域信息与用户枚举**：如 net、net view、net group、net user、net group "Domain Admins" /domain、dsquery、dsget、adfind、adenum、ldapsearch、bloodhound、SharpHound、crackmapexec、rpcclient、GetADUser、GetADComputer、Get-DomainUser、Get-DomainGroup、Get-DomainTrust、Get-DomainPolicy、powerview。
*   **Kerberos信息收集**：如 kerbrute、GetNPUsers.py、GetUserSPNs.py、impacket工具集。
*   **GPO与信任关系枚举**：如 gpresult、adfind、bloodhound、powerview。

**3. 漏洞分析与利用 (Vulnerability Analysis & Exploitation)**
*   **Web漏洞**：
    *   SQL注入（sqlmap、NoSQLMap、手工payload、sqlninja、jSQL）
    *   XSS（手工payload、XSStrike、dalfox、xsscrapy）
    *   文件包含/上传/解析（wfuzz、burp、ffuf、lfi-autopwn、fimap、upload bypass）
    *   SSRF、SSTI、模板注入（tplmap、手工payload）
    *   HTTP请求走私（h2csmuggler、smuggler、burp插件）
    *   反序列化（ysoserial、phpggc、gadgetinspector）
    *   认证绕过、逻辑漏洞、CORS、IDOR、JWT攻击
*   **CMS与常见服务漏洞**：
    *   WordPress（wpscan、漏洞利用、插件/主题检测）
    *   Jenkins、Drupal、Joomla、Struts2、ThinkPHP、Discuz、phpMyAdmin、Koken、Moodle、October CMS
*   **协议与服务漏洞**：
    *   POP3/IMAP/SMTP/FTP/SSH/Telnet/WinRM/TFTP（hydra、medusa、ncrack、evil-winrm、msfconsole、telnet、ftp、ssh、tftp、smtp-user-enum、smtp-vrfy）
    *   RDP（rdp-sec-check、crowbar、ncrack）
    *   VNC、MySQL、MSSQL、Oracle、Redis、MongoDB、Memcached、Elasticsearch、Rsync、NFS、Docker、Kubernetes
*   **Windows/AD攻击**：
    *   mimikatz、secretsdump.py、impacket、kerbrute、rubeus、crackmapexec、bloodhound、SharpHound、lsassy、PetitPotam、PrintNightmare、ZeroLogon
*   **Linux提权与利用**：
    *   linpeas、linux-exploit-suggester、pspy、sudo提权、capabilities、SUID/SGID、环境变量、计划任务、NFS、Docker/LXC逃逸
*   **漏洞利用框架**：
    *   Metasploit、Cobalt Strike、Nuclei、Exploit-DB、searchsploit、msfvenom

**4. 其他技巧与辅助工具**
*   **信息泄露与敏感文件查找**：如 git-dumper、truffleHog、gitrob、find、grep、strings、binwalk、exiftool。
*   **自动化与脚本**：如 autorecon、nmapAutomator、AutoBlue-MS17-010、MS17-010-Scanner、masscan、onesixtyone。
*   **社会工程与钓鱼**：如 SET、gophish、evilginx2。
*   **云服务攻击**：如 pacu、ScoutSuite、S3Scanner、cloud_enum。

请输出每个命令，并简要说明其用途和适用场景。可以适当补充常见payload和Bypass技巧。
请详细输出，不用担心内容过长或token浪费，越详细越好。'''
        
        # 添加扫描结果到提示中
        for result in results:
            prompt += f"\n文件: {result['file']}\n内容:\n{result['content'][:1000]}\n"  # 限制每个文件的内容长度
            
        try:
            logger.info("Sending request to DeepSeek API...")
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "你是一个专业的红队专家，擅长分析目标系统的弱点和攻击路径。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=5000
            )
            logger.info("Received response from DeepSeek API.")
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"AI分析过程中出错: {str(e)}")
            return f"AI分析过程中出错: {str(e)}"

# 创建全局AI分析器实例
analyzer = AutoReconAnalyzer()

# ============================================================================
# 全局数据存储
# ============================================================================

# 存储分析结果
analysis_results: Dict[str, Dict] = {}

# 存储扫描状态和日志
scan_status: Dict[str, Dict] = {}
MAX_SCAN_STATUS_ENTRIES = 10  # 最多保留10个扫描状态

# ============================================================================
# 扫描状态管理函数
# ============================================================================

def cleanup_old_scan_status():
    """
    清理旧的扫描状态，保持字典大小在限制内
    
    当扫描状态条目超过最大限制时，删除最旧的条目以避免内存泄漏
    """
    if len(scan_status) > MAX_SCAN_STATUS_ENTRIES:
        # 按开始时间排序，删除最旧的条目
        sorted_scans = sorted(scan_status.items(), key=lambda x: x[1].get('start_time', datetime.min))
        scans_to_remove = len(scan_status) - MAX_SCAN_STATUS_ENTRIES
        
        for i in range(scans_to_remove):
            scan_id = sorted_scans[i][0]
            del scan_status[scan_id]
            logger.info(f"Cleaned up old scan status: {scan_id}")

def cleanup_completed_scan(scan_id: str):
    """
    清理已完成的扫描状态
    
    Args:
        scan_id (str): 要清理的扫描ID
    """
    if scan_id in scan_status:
        # 保留基本信息，清理大量日志数据
        scan_status[scan_id]["logs"] = scan_status[scan_id]["logs"][-100:]  # 只保留最后100条日志
        logger.info(f"Cleaned up completed scan: {scan_id}")

def find_node_in_tree(tree, node_name):
    """
    在树状结构中查找指定名称的节点
    
    Args:
        tree (Dict): 树状结构数据
        node_name (str): 要查找的节点名称
        
    Returns:
        Dict: 找到的节点，如果未找到返回None
    """
    if tree["name"] == node_name:
        return tree
    if "children" in tree:
        for child in tree["children"]:
            found_node = find_node_in_tree(child, node_name)
            if found_node:
                return found_node
    return None

def parse_nmap_results(results_dir: str) -> Dict:
    """
    解析Nmap扫描结果
    
    从AutoRecon结果目录中解析Nmap XML文件，提取开放端口和服务信息
    
    Args:
        results_dir (str): AutoRecon结果目录路径
        
    Returns:
        Dict: 包含主机IP和开放端口服务信息的字典
    """
    nmap_data = {}
    logger.info(f"Parsing Nmap results from: {results_dir}")
    
    # results_dir 已经是 results/<ip> 这样的路径
    target_ip = os.path.basename(results_dir)
    autorecon_output_base_path = os.path.join(results_dir)
    scans_base_path = os.path.join(autorecon_output_base_path, 'scans')

    # 初始化目标IP的数据结构
    nmap_data[target_ip] = {"services": {}}

    # 遍历所有端口目录和xml目录下的_nmap.xml文件
    for root, dirs, files in os.walk(scans_base_path):
        for file in files:
            if file.endswith('_nmap.xml'):
                file_path = os.path.join(root, file)
                try:
                    tree = ET.parse(file_path)
                    root_elem = tree.getroot()
                    
                    for host_elem in root_elem.findall('host'):
                        # For autorecon, the Nmap results are usually for the target_ip itself
                        for port_elem in host_elem.findall('ports/port'):
                            state_elem = port_elem.find('state')
                            if state_elem is not None and state_elem.get('state') == 'open':
                                port_id = port_elem.get('portid')
                                service_elem = port_elem.find('service')
                                if service_elem is not None:
                                    service_name = service_elem.get('name')
                                    if port_id and service_name:
                                        nmap_data[target_ip]["services"][port_id] = service_name
                    logger.info(f"Parsed Nmap XML: {file_path}")
                except Exception as e:
                    logger.error(f"Error parsing Nmap XML {file_path}: {str(e)}")
            
    logger.info(f"Found {len(nmap_data)} hosts with Nmap results")
    return nmap_data

def parse_vulnerability_data(results_dir: str) -> Dict:
    """
    解析漏洞扫描结果
    
    从AutoRecon结果目录中解析各种漏洞扫描工具的输出，
    包括Nikto、Enum4Linux、SMBMap等工具的结果
    
    Args:
        results_dir (str): AutoRecon结果目录路径
        
    Returns:
        Dict: 包含主机IP和漏洞信息的字典
    """
    vuln_data = {}
    logger.info(f"Parsing vulnerability data from: {results_dir}")

    # results_dir 已经是 results/<ip> 这样的路径
    target_ip = os.path.basename(results_dir)
    autorecon_output_base_path = os.path.join(results_dir)

    # 遍历所有服务目录下的报告文件
    services_report_path = os.path.join(autorecon_output_base_path, 'report', 'report.md', target_ip, 'Services')
    if os.path.exists(services_report_path):
        for service_dir_name in os.listdir(services_report_path):
            service_dir_path = os.path.join(services_report_path, service_dir_name)
            if os.path.isdir(service_dir_path):
                # 使用正则表达式解析服务目录名称，提取协议、端口和服务名
                match = re.search(r'Service - (tcp|udp)-(\d+)-(.+)', service_dir_name)
                if match:
                    protocol = match.group(1)
                    port = match.group(2)
                    service_name = match.group(3)
                    
                    host_ip = target_ip
                    if host_ip not in vuln_data:
                        vuln_data[host_ip] = []

                    # 检查扫描目录中的工具输出
                    scan_dir = os.path.join(autorecon_output_base_path, 'scans', f'{protocol}{port}')
                    if os.path.exists(scan_dir):
                        for file_name in os.listdir(scan_dir):
                            file_path = os.path.join(scan_dir, file_name)
                            if os.path.isfile(file_path):
                                try:
                                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()

                                    # 解析Nikto扫描结果
                                    if "nikto" in file_name.lower():
                                        findings = re.findall(r'\+ (.*)', content)
                                        if findings:
                                            for finding in findings:
                                                vuln_info = {
                                                    "name": f"Nikto: {finding.strip()[:50]}...",
                                                    "severity": "high",
                                                    "description": finding.strip(),
                                                    "affected_services": [f"{service_name} ({port})"]
                                                }
                                                vuln_data[host_ip].append(vuln_info)
                                        else:
                                            vuln_data[host_ip].append({
                                                "name": "Nikto Scan (No specific findings listed)",
                                                "severity": "info",
                                                "description": "Nikto scan ran, no detailed findings extracted or found.",
                                                "affected_services": [f"{service_name} ({port})"]
                                            })

                                    # 解析Enum4Linux扫描结果
                                    elif "enum4linux" in file_name.lower():
                                        if "no null session" not in content.lower() and "failed to connect" not in content.lower():
                                            vuln_data[host_ip].append({
                                                "name": "Enum4Linux (Potential SMB/NFS Vuln)",
                                                "severity": "medium",
                                                "description": "Enum4Linux output suggests potential SMB/NFS enumeration findings. Review full log.",
                                                "affected_services": [f"{service_name} ({port})"]
                                            })
                                        else:
                                            vuln_data[host_ip].append({
                                                "name": "Enum4Linux (No significant findings)",
                                                "severity": "info",
                                                "description": "Enum4linux ran, no significant findings detected.",
                                                "affected_services": [f"{service_name} ({port})"]
                                            })

                                    # 解析SMBMap扫描结果
                                    elif "smbmap" in file_name.lower():
                                        if "read" in content.lower() or "write" in content.lower():
                                            vuln_data[host_ip].append({
                                                "name": "SMBMap (Share Permissions Found)",
                                                "severity": "high",
                                                "description": "SMBMap found accessible shares with read/write permissions. Review full log.",
                                                "affected_services": [f"{service_name} ({port})"]
                                            })
                                        else:
                                            vuln_data[host_ip].append({
                                                "name": "SMBMap (No interesting permissions)",
                                                "severity": "info",
                                                "description": "SMBMap ran, no interesting share permissions found.",
                                                "affected_services": [f"{service_name} ({port})"]
                                            })
                                    
                                    # 解析Nbtscan扫描结果
                                    elif "nbtscan" in file_name.lower():
                                        if "name server" in content.lower() and "<00>" in content.lower():
                                            vuln_data[host_ip].append({
                                                "name": "Nbtscan (NetBIOS Info Found)",
                                                "severity": "info",
                                                "description": "Nbtscan found NetBIOS information. Review for sensitive data.",
                                                "affected_services": [f"{service_name} ({port})"]
                                            })

                                except Exception as e:
                                    logger.error(f"Error reading or parsing vulnerability file {file_path}: {str(e)}")
                    else:
                        logger.warning(f"Scan directory not found for service {service_name} ({port}): {scan_dir}")
                else:
                    logger.warning(f"Service directory name did not match regex: {service_dir_name}")
            else:
                logger.warning(f"Skipping non-directory item in services report path: {service_dir_path}")
    else:
        logger.warning(f"Services report path not found: {services_report_path}")

    logger.info(f"Finished parsing vulnerability data. Final vuln_data count: {sum(len(v) for v in vuln_data.values())} across hosts.")
    return vuln_data

def generate_network_graph(nmap_data: Dict, vuln_data: Dict) -> Dict:
    """
    生成网络关系树状图数据
    
    将Nmap扫描结果和漏洞数据转换为前端可视化所需的树状结构
    
    Args:
        nmap_data (Dict): Nmap扫描结果数据
        vuln_data (Dict): 漏洞扫描结果数据
        
    Returns:
        Dict: 树状结构的网络拓扑图数据
    """
    logger.info("Generating network tree graph")
    
    tree_data = {
        "name": "AutoRecon Results",
        "children": [],
        "attributes": {"type": "root"}
    }

    for host_ip, host_info in nmap_data.items():
        host_node = {
            "name": host_ip,
            "attributes": {"type": "host", "ip": host_ip},
            "children": []
        }

        # Add services/ports as children of hosts
        for port, service_name in host_info.get("services", {}).items():
            service_node = {
                "name": f"Port {port} ({service_name})",
                "attributes": {"type": "service", "port": port, "service_name": service_name},
                "children": []
            }
            host_node["children"].append(service_node)

            # Add vulnerabilities related to this service
            # Create a string that matches the format in affected_services from parse_vulnerability_data
            service_identifier = f"{service_name} ({port})"
            for vuln_info in vuln_data.get(host_ip, []):
                if service_identifier in vuln_info.get("affected_services", []):
                    
                    # Create a more detailed name for the vulnerability node
                    display_name = vuln_info["name"]
                    if len(vuln_info["description"]) > 50 and "Nikto: " in vuln_info["name"]:
                        # For Nikto findings, try to extract a more concise summary from description
                        summary_match = re.search(r'^\S.*?:\s*(.+?)(?:\s*See:|$)', vuln_info["description"])
                        if summary_match:
                            display_name = f"[{vuln_info['severity'].title()}] {summary_match.group(1)[:50]}..."
                        else:
                            display_name = f"[{vuln_info['severity'].title()}] {vuln_info['name']}"
                    else:
                        display_name = f"[{vuln_info['severity'].title()}] {vuln_info['name']}"
                    
                    vuln_node = {
                        "name": display_name,
                        "attributes": {
                            "type": "vulnerability",
                            "severity": vuln_info["severity"],
                            "description": vuln_info["description"]
                        },
                        "children": []
                    }
                    service_node["children"].append(vuln_node)

        tree_data["children"].append(host_node)

    logger.info(f"Generated network graph with {len(tree_data['children'])} hosts")
    return tree_data

@app.post("/upload")
async def upload_directory(files: List[UploadFile] = File(...)):
    """处理上传的results目录"""
    try:
        # 创建临时目录
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_dir = f"temp_{timestamp}"
        os.makedirs(temp_dir, exist_ok=True)
        logger.info(f"Created temporary directory: {temp_dir}")
        
        # 保存上传的文件
        for file in files:
            # 获取相对路径
            # Note: file.filename contains the full relative path from the selected directory root
            relative_path = file.filename
            # Create target directory
            target_path = os.path.join(temp_dir, relative_path)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            
            logger.info(f"Saving file: {relative_path} to {target_path}")
            
            # Save file
            async with aiofiles.open(target_path, 'wb') as out_file:
                content = await file.read()
                await out_file.write(content)
        
        # 解析结果
        nmap_data = parse_nmap_results(temp_dir)
        vuln_data = parse_vulnerability_data(temp_dir)
        
        # 生成网络图 (now tree data)
        graph_data = generate_network_graph(nmap_data, vuln_data)
        
        # 保存分析结果
        analysis_id = f"analysis_{timestamp}"
        analysis_results[analysis_id] = {
            "nmap_data": nmap_data,
            "vuln_data": vuln_data,
            "graph_data": graph_data,
            "timestamp": timestamp
        }
        
        # 清理临时文件
        shutil.rmtree(temp_dir)
        logger.info(f"Cleaned up temporary directory: {temp_dir}")
        
        response_data = {
            "analysis_id": analysis_id,
            "message": "Analysis completed successfully",
            "graph_data": graph_data # This now contains tree data
        }
        logger.info(f"Sending response with root node and {len(graph_data['children'])} top-level children")
        return JSONResponse(response_data)
        
    except Exception as e:
        logger.error(f"Error processing directory: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/annotate_node")
async def annotate_node(request: AnnotationRequest):
    """为指定分析中的节点添加批注子节点"""
    if request.analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    tree_data = analysis_results[request.analysis_id]["graph_data"]
    parent_node = find_node_in_tree(tree_data, request.parent_node_name)
    
    if not parent_node:
        raise HTTPException(status_code=404, detail=f"Parent node {request.parent_node_name} not found")
    
    # 创建批注子节点
    annotation_node = {
        "name": f"Annotation ({datetime.now().strftime('%H:%M:%S')})",
        "attributes": {
            "type": "annotation",
            "text": request.annotation_text
        },
        "children": []
    }
    
    # 确保父节点有children数组
    if "children" not in parent_node:
        parent_node["children"] = []
    
    # 添加批注子节点
    parent_node["children"].append(annotation_node)
    
    return {"message": "Annotation added successfully"}

@app.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """获取分析结果"""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis_results[analysis_id]

def find_and_remove_node(tree, node_name):
    """在树中查找并删除指定节点"""
    if not tree:
        return False
    
    # 检查当前节点的子节点
    if "children" in tree:
        for i, child in enumerate(tree["children"]):
            if child["name"] == node_name:
                # 找到节点，删除它
                tree["children"].pop(i)
                return True
            # 递归检查子节点
            if find_and_remove_node(child, node_name):
                return True
    return False

@app.post("/delete_node")
async def delete_node(request: DeleteNodeRequest):
    """删除指定分析中的节点"""
    if request.analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    tree_data = analysis_results[request.analysis_id]["graph_data"]
    
    # 不允许删除根节点
    if tree_data["name"] == request.node_name:
        raise HTTPException(status_code=400, detail="Cannot delete root node")
    
    # 尝试删除节点
    if find_and_remove_node(tree_data, request.node_name):
        logger.info(f"Node '{request.node_name}' deleted from analysis '{request.analysis_id}'")
        return {"message": "Node deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail=f"Node {request.node_name} not found")

# ============================================================================
# 核心扫描功能
# ============================================================================

def run_autorecon(ip: str, scan_id: str):
    """
    在后台运行AutoRecon扫描
    
    启动AutoRecon工具对指定IP进行全面的渗透测试扫描，
    包括端口扫描、服务识别、漏洞扫描等
    
    Args:
        ip (str): 目标IP地址
        scan_id (str): 扫描任务ID
    """
    try:
        # 只用results目录，AutoRecon会自动在里面创建ip子目录
        results_dir = "results"
        os.makedirs(results_dir, exist_ok=True)
        
        # 运行AutoRecon命令
        process = subprocess.Popen(
            ["autorecon", ip, "-o", results_dir, "--ignore-plugin-checks", "--disable-keyboard-control"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # 将实际的 results_dir 路径存储到 scan_status 中，以便后续获取结果
        scan_status[scan_id]["results_dir"] = os.path.join(results_dir, ip)
        
        # 读取输出，添加超时和限制
        start_time = time.time()
        max_duration = 3600  # 最大运行1小时
        max_logs = 1000  # 减少最大日志条数到1000
        
        while True:
            # 检查超时
            if time.time() - start_time > max_duration:
                logger.warning(f"AutoRecon scan for {ip} timed out after {max_duration} seconds")
                process.terminate()
                scan_status[scan_id]["status"] = "failed"
                scan_status[scan_id]["error"] = "Scan timed out"
                cleanup_completed_scan(scan_id)
                cleanup_old_scan_status()
                break
            
            # 检查日志数量限制
            if len(scan_status[scan_id]["logs"]) > max_logs:
                logger.warning(f"AutoRecon scan for {ip} exceeded log limit ({max_logs})")
                process.terminate()
                scan_status[scan_id]["status"] = "failed"
                scan_status[scan_id]["error"] = "Too many log entries"
                cleanup_completed_scan(scan_id)
                cleanup_old_scan_status()
                break
            
            # 使用select进行非阻塞读取，避免CPU占用过高
            ready, _, _ = select.select([process.stdout], [], [], 1.0)  # 1秒超时
            
            if ready:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    scan_status[scan_id]["logs"].append(output.strip())
                    # 限制日志数组大小，只保留最新的日志
                    if len(scan_status[scan_id]["logs"]) > max_logs:
                        scan_status[scan_id]["logs"] = scan_status[scan_id]["logs"][-max_logs:]
            else:
                # 如果没有输出，检查进程是否还在运行
                if process.poll() is not None:
                    break
            
            # 增加延迟，减少CPU占用
            time.sleep(0.1)  # 增加到100ms
        
        # 检查扫描结果
        if process.returncode == 0:
            scan_status[scan_id]["status"] = "completed"
            logger.info(f"AutoRecon scan for {ip} completed successfully")
        else:
            scan_status[scan_id]["status"] = "failed"
            scan_status[scan_id]["error"] = "AutoRecon scan failed"
            logger.error(f"AutoRecon scan for {ip} failed with return code: {process.returncode}")
        
        # 清理扫描状态
        cleanup_completed_scan(scan_id)
        cleanup_old_scan_status()
            
    except Exception as e:
        scan_status[scan_id]["status"] = "failed"
        scan_status[scan_id]["error"] = str(e)
        logger.error(f"Exception in AutoRecon scan for {ip}: {str(e)}")
        cleanup_completed_scan(scan_id)
        cleanup_old_scan_status()

# ============================================================================
# API端点定义
# ============================================================================

@app.post("/scan")
async def start_scan(request: ScanRequest):
    """
    启动新的扫描任务
    
    接收扫描请求，检查现有结果，启动AutoRecon扫描
    
    Args:
        request (ScanRequest): 包含目标IP和覆盖选项的扫描请求
        
    Returns:
        JSONResponse: 包含扫描ID和状态信息的响应
    """
    ip = request.ip
    overwrite = request.overwrite  # Get the overwrite flag from the request
    
    # 在开始新扫描前清理旧的扫描状态
    cleanup_old_scan_status()
    
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = {"status": "pending", "logs": [], "start_time": datetime.now(), "ip": ip}

    # Define paths
    results_dir = os.path.join("results", ip)

    # 如果results/<ip>目录已存在
    if os.path.exists(results_dir):
        if overwrite:
            logger.info(f"Overwriting existing results for {ip}. Deleting directory: {results_dir}")
            try:
                shutil.rmtree(results_dir)
                logger.info(f"Successfully deleted {results_dir}")
            except OSError as e:
                logger.error(f"Error deleting directory {results_dir}: {e}")
                raise HTTPException(status_code=500, detail=f"Failed to delete existing results: {e}")
        else:
            logger.info(f"Results for {ip} already exist and overwrite is False. Not starting new scan.")
            return JSONResponse({
                "message": f"Results for {ip} already exist. Set overwrite=True to rescan.",
                "scan_id": None,
                "ip": ip
            })

    # Start AutoRecon in a separate thread
    thread = Thread(target=run_autorecon, args=(ip, scan_id))
    thread.daemon = True
    thread.start()

    return JSONResponse({"message": "Scan initiated", "scan_id": scan_id, "ip": ip})

@app.get("/scan_status/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    获取扫描状态和日志
    
    返回指定扫描任务的当前状态、日志和错误信息
    
    Args:
        scan_id (str): 扫描任务ID
        
    Returns:
        Dict: 包含扫描状态、日志和错误信息的字典
    """
    logger.info(f"Received request for scan status for scan_id: {scan_id}")
    if scan_id not in scan_status:
        logger.error(f"Scan with scan_id: {scan_id} not found.")
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = scan_status[scan_id]
    all_logs = status["logs"]  # 返回所有已累积的日志
    
    logger.info(f"Returning status '{status['status']}' for scan_id: {scan_id}")
    return {
        "status": status["status"],
        "new_logs": all_logs,
        "error": status.get("error")
    }

@app.get("/check_results_exists/{ip}")
async def check_results_exists(ip: str):
    """
    检查指定IP的扫描结果是否存在
    
    Args:
        ip (str): 目标IP地址
        
    Returns:
        Dict: 包含结果存在状态的字典
    """
    logger.info(f"Received request to check results existence for IP: {ip}")
    # 检查 results/<ip> 目录是否存在
    results_path = Path(f"results/{ip}")
    exists = results_path.is_dir()
    logger.info(f"Results for IP: {ip} exists: {exists}")
    return {"exists": exists}

@app.get("/load_existing_results/{ip}")
async def load_existing_results(ip: str):
    """
    加载指定IP的现有扫描结果
    
    解析并返回已存在的扫描结果，包括网络拓扑图数据
    
    Args:
        ip (str): 目标IP地址
        
    Returns:
        Dict: 包含网络拓扑图数据的字典
    """
    logger.info(f"Received request to load existing results for IP: {ip}")
    # 只检查 results/<ip> 目录
    results_root_dir = f"results/{ip}"
    if not Path(results_root_dir).is_dir():
        logger.error(f"Results for IP: {ip} not found at {results_root_dir}")
        raise HTTPException(status_code=404, detail="Results for this IP not found")

    nmap_data = parse_nmap_results(results_root_dir)
    vuln_data = parse_vulnerability_data(results_root_dir)
    graph_data = generate_network_graph(nmap_data, vuln_data)

    logger.info(f"Successfully loaded existing results for IP: {ip}")
    return {
        "graph_data": graph_data,
        "message": "Existing results loaded successfully"
    }

@app.get("/scan_results/{scan_id}")
async def get_scan_results(scan_id: str):
    """
    获取扫描结果
    
    解析并返回指定扫描任务的完整结果，包括网络拓扑图数据
    
    Args:
        scan_id (str): 扫描任务ID
        
    Returns:
        Dict: 包含网络拓扑图数据的字典
    """
    logger.info(f"Received request for scan results for scan_id: {scan_id}")
    if scan_id not in scan_status:
        logger.error(f"Scan with scan_id: {scan_id} not found for results.")
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_status[scan_id]["status"] != "completed":
        logger.warning(f"Scan with scan_id: {scan_id} not completed yet. Current status: {scan_status[scan_id]['status']}")
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    # 获取扫描时存储的 IP 地址，以构建正确的 results_dir
    scanned_ip = scan_status[scan_id].get("ip")
    if not scanned_ip:
        logger.error(f"Scanned IP not found for scan ID: {scan_id}.")
        raise HTTPException(status_code=500, detail="Scanned IP not found for this scan ID.")

    results_dir_for_parsing = f"results/{scanned_ip}"
    
    nmap_data = parse_nmap_results(results_dir_for_parsing)
    vuln_data = parse_vulnerability_data(results_dir_for_parsing)
    graph_data = generate_network_graph(nmap_data, vuln_data)
    
    logger.info(f"Successfully processed scan results for scan_id: {scan_id}")
    return {
        "graph_data": graph_data,
        "message": "Results processed successfully"
    }

@app.get("/analyze_scan_results/{ip}")
async def analyze_scan_results(ip: str):
    """
    自动调用DeepSeek分析AutoRecon扫描结果
    
    使用AI对扫描结果进行智能分析，生成渗透测试建议
    
    Args:
        ip (str): 目标IP地址
        
    Returns:
        Dict: 包含AI分析报告的字典
    """
    logger.info(f"Received request to analyze scan results for IP: {ip}")
    results_path = f"results/{ip}"  # 修正为只查找 results/{ip}

    if not Path(results_path).is_dir():
        logger.error(f"AutoRecon results not found for IP: {ip} at path: {results_path}")
        raise HTTPException(status_code=404, detail=f"AutoRecon results not found for IP: {ip}")
    
    logger.info(f"Starting AI analysis for IP: {ip} from path: {results_path}")
    raw_results = analyzer.read_results(results_path)
    if not raw_results:
        logger.warning(f"No raw results found for IP: {ip} to analyze.")
        return {"analysis_report": "未能读取到任何有效的AutoRecon结果文件进行分析。"}
        
    analysis = analyzer.analyze_results(raw_results)
    logger.info(f"AI analysis completed for IP: {ip}. Report length: {len(analysis)} characters.")
    
    return {"analysis_report": analysis}

@app.post("/upload_compressed_results")
async def upload_compressed_results(file: UploadFile = File(...)):
    """
    上传压缩的AutoRecon结果文件
    
    支持上传ZIP、TAR.GZ等压缩格式的AutoRecon扫描结果，
    自动解压并解析结果数据
    
    Args:
        file (UploadFile): 上传的压缩文件
        
    Returns:
        Dict: 包含上传状态和解析结果的字典
    """
    try:
        # 创建临时目录
        temp_dir = "temp_compressed"
        os.makedirs(temp_dir, exist_ok=True)
        
        # 保存上传的文件
        file_path = os.path.join(temp_dir, file.filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # 解压文件
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        # 根据文件扩展名选择解压方法
        if file.filename.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif file.filename.endswith('.tar.gz') or file.filename.endswith('.tgz'):
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_dir)
        elif file.filename.endswith('.tar'):
            with tarfile.open(file_path, 'r') as tar_ref:
                tar_ref.extractall(extract_dir)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format")
        
        # 移动解压的内容到results目录
        results_dir = "results"
        os.makedirs(results_dir, exist_ok=True)
        
        # 查找解压后的IP目录
        extracted_contents = os.listdir(extract_dir)
        uploaded_ip = None
        
        if len(extracted_contents) == 1 and os.path.isdir(os.path.join(extract_dir, extracted_contents[0])):
            # 如果只有一个目录，假设它是IP目录
            ip_dir = extracted_contents[0]
            source_path = os.path.join(extract_dir, ip_dir)
            target_path = os.path.join(results_dir, ip_dir)
            
            if os.path.exists(target_path):
                shutil.rmtree(target_path)
            
            shutil.move(source_path, target_path)
            uploaded_ip = ip_dir
            logger.info(f"Successfully uploaded and extracted results for IP: {ip_dir}")
        else:
            # 如果有多个文件/目录，直接移动到results
            for item in extracted_contents:
                source_path = os.path.join(extract_dir, item)
                target_path = os.path.join(results_dir, item)
                
                if os.path.exists(target_path):
                    if os.path.isdir(target_path):
                        shutil.rmtree(target_path)
                    else:
                        os.remove(target_path)
                
                shutil.move(source_path, target_path)
            
            logger.info("Successfully uploaded and extracted results")
            return {"message": "Successfully uploaded results"}
        
        # 解析上传的结果并返回graph_data
        if uploaded_ip:
            try:
                results_root_dir = f"results/{uploaded_ip}"
                nmap_data = parse_nmap_results(results_root_dir)
                vuln_data = parse_vulnerability_data(results_root_dir)
                graph_data = generate_network_graph(nmap_data, vuln_data)
                
                logger.info(f"Successfully parsed uploaded results for IP: {uploaded_ip}")
                return {
                    "message": f"Successfully uploaded results for IP: {uploaded_ip}",
                    "ip": uploaded_ip,
                    "graph_data": graph_data
                }
            except Exception as parse_err:
                logger.error(f"Error parsing uploaded results for IP {uploaded_ip}: {str(parse_err)}")
                return {
                    "message": f"Successfully uploaded results for IP: {uploaded_ip}, but failed to parse: {str(parse_err)}",
                    "ip": uploaded_ip
                }
            
    except Exception as e:
        logger.error(f"Error uploading compressed results: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
    finally:
        # 清理临时文件
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
        except Exception as e:
            logger.warning(f"Error cleaning up temporary files: {str(e)}")

@app.post("/cleanup_scan_status")
async def cleanup_scan_status():
    """
    手动清理所有扫描状态
    
    用于紧急清理所有扫描状态数据，释放内存
    
    Returns:
        Dict: 包含清理结果的字典
    """
    try:
        global scan_status
        old_count = len(scan_status)
        scan_status.clear()
        logger.info(f"Manually cleaned up {old_count} scan status entries")
        return {"message": f"Cleaned up {old_count} scan status entries"}
    except Exception as e:
        logger.error(f"Error cleaning up scan status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")

@app.get("/scan_status_count")
async def get_scan_status_count():
    """
    获取当前扫描状态数量
    
    返回当前活跃的扫描任务数量和最大限制
    
    Returns:
        Dict: 包含扫描状态数量和最大限制的字典
    """
    return {"count": len(scan_status), "max_entries": MAX_SCAN_STATUS_ENTRIES}

# ============================================================================
# 应用启动
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    # 启动FastAPI应用服务器
    uvicorn.run(app, host="0.0.0.0", port=8000) 