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
import re # Add this import for regex
from pydantic import BaseModel # Import BaseModel
import subprocess
import asyncio
import uuid
from threading import Thread
import queue
import xml.etree.ElementTree as ET # Import ElementTree for XML parsing
from openai import OpenAI
from dotenv import load_dotenv
import httpx # Import httpx
import zipfile # Add zipfile import
import tarfile # Add tarfile import

# Load environment variables
load_dotenv()

# Define Pydantic model for annotation request
class AnnotationRequest(BaseModel):
    analysis_id: str
    parent_node_name: str # Changed from node_name to parent_node_name
    annotation_text: str # Changed from annotation to annotation_text

class DeleteNodeRequest(BaseModel):
    analysis_id: str
    node_name: str

# Define Pydantic models
class ScanRequest(BaseModel):
    ip: str
    overwrite: bool = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/ping")
async def ping():
    return {"message": "pong"}

# Initialize OpenAI client globally
class AutoReconAnalyzer:
    def __init__(self):
        api_key = os.getenv('DEEPSEEK_API_KEY')
        if not api_key:
            logger.error("DEEPSEEK_API_KEY environment variable not found. AI analysis will not be available.")
            self.client = None
            return
        logger.info("DEEPSEEK_API_KEY loaded successfully. Initializing DeepSeek AI client.")
        
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com/v1",
            http_client=httpx.Client() # Explicitly set no proxies
        )
        logger.info("DeepSeek AI client initialized.")
        
    def read_results(self, results_path):
        """读取AutoRecon的结果文件"""
        logger.info(f"Attempting to read AutoRecon results from: {results_path}")
        results = []
        path = Path(results_path)
        
        if not path.exists():
            logger.error(f"错误: 指定的AutoRecon结果路径不存在: {results_path}")
            return None
            
        # 递归遍历所有文本文件
        for file_path in path.rglob("*.txt"): # Only process .txt files for analysis
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():  # 只添加非空文件
                        results.append({
                            "file": str(file_path.relative_to(path)), # Store relative path
                            "content": content
                        })
                        logger.debug(f"Successfully read file: {file_path}")
            except Exception as e:
                logger.warning(f"警告: 无法读取文件 {file_path}: {str(e)}")
                
        logger.info(f"Finished reading results. Found {len(results)} valid text files.")
        return results

    def analyze_results(self, results):
        """使用AI分析AutoRecon的结果"""
        logger.info("Starting AI analysis...")
        if not self.client:
            logger.error("AI analysis client is not initialized. Cannot proceed with analysis.")
            return "AI分析服务未初始化，因为缺少API密钥。"

        if not results:
            logger.warning("No results provided for AI analysis.")
            return "没有找到可分析的结果。"
            
        # 准备提示信息
        prompt = """你是一位经验丰富的渗透测试专家。你收到了一份 AutoRecon 的扫描结果报告（包含 Nmap 扫描、漏洞扫描、开放端口信息等）。请根据这些结果，生成一份详细的渗透测试命令清单，列出下一步可能采取的攻击或信息收集命令。请将命令分为以下几个类别：

**1. 信息收集与侦察 (Reconnaissance)**
*   **主机发现与端口扫描**：`nmap` 和 `powershell` 命令，用于进一步确认开放端口、服务版本和操作系统。具体包括：
    *   主机发现：`sudo nmap -sn <本机ip的网段>`
    *   初步探测端口、服务版本和操作系统：`sudo nmap -sT -sV -O -p- <IP>`
    *   默认脚本扫描：`sudo nmap -sT -sC <IP>`
    *   默认漏洞脚本扫描：`sudo nmap --script=vuln <IP>`
    *   UDP扫描：`sudo nmap -sU -sV -O --top-ports 20 --min-rate 5000 <IP>`
    *   PowerShell 端口扫描：`1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect(\"192.168.50.151\", $_)) \"TCP port $_ is open\"} 2>$null`
*   **子域名与DNS信息枚举**：
    *   `nslookup` (Windows) 查询域名、任何类型记录和邮件服务器的命令。
    *   `dnsenum` 进行域名枚举和区域传输测试的命令。
    *   `dnsrecon` 进行域名枚举、区域传输和 Google Dorking 的命令。
    *   `ffuf` 和 `gobuster` 进行子域名和目录爆破的命令。
    *   `wfuzz` 进行子域名和目录爆破（绕过 404）的命令。
*   **SMB/NetBIOS 信息收集**：
    *   `enum4linux` 获取 SMB 共享和用户信息的命令。
    *   `smbmap` 列出 SMB 共享内容，并进行认证登录的命令。
    *   `crackmapexec smb` 枚举共享、用户和执行命令的命令。
    *   `nbtscan` 扫描 NetBIOS 的命令。
*   **LDAP 信息收集**：
    *   `windapsearch` 枚举 LDAP 用户和组的命令。
    *   `ldapsearch` 查询 LDAP 目录的命令。
*   **SNMP 信息收集**：
    *   `onesixtyone` 扫描 SNMP 团体字符串的命令。
    *   `snmpwalk` 枚举 MIB tree、用户、进程、已安装软件和监听端口的命令。
*   **网络流量分析**：
    *   `tcpdump` 捕获 ICMP 流量的命令。
    *   `tshark` 捕获、保存、读取、解码和过滤网络流量（例如提取凭据、过滤用户代理）的命令。
    *   `responder` 监听网络流量的命令。
*   **被动信息收集**：提及 Wappalyzer, BuiltWith, Shodan, Censys, Hunter.io, TheHarvester 等工具。
*   **Google Hacking / Dorking**：`site:`, `filetype:`, `ext:`, `intitle:` 等高级搜索语法及其用途。
*   **AutoRecon**：明确运行 `autorecon <target_ip>` 作为初步信息收集工具。

**2. 漏洞分析与利用 (Vulnerability Analysis & Exploitation)**
*   **Web 漏洞**：
    *   **SQL 注入**：MySQL 和 MSSQL 的查询、盲注（基于长度、字符、时间、ASCII）、报错注入、UNION 查询、高级绕过Payload、`group_concat()` 和 `sqlmap` 命令。
    *   **XSS (跨站脚本)**：检查 `httponly`/`secure`，绕过 CSRF (nonce 获取)，会话窃取和键盘记录的 JavaScript 代码。
    *   **文件包含**：常见敏感日志文件路径，Session 包含/注入。
    *   **HTTP 请求走私**：`h2csmuggler` 命令。
    *   **RTF/HTA Getshell**：利用 CVE-2017-0199 构造 RTF，`msfvenom` 生成 HTA 木马。
*   **CMS 漏洞**：
    *   **Jenkins**：利用 `build now`、定时任务和远程触发 `build` 执行 RCE 的命令和 `curl` 远程触发示例。
    *   **WordPress**：`wpscan` 命令，文件上传漏洞 (CVE-2019-8942) 利用。
    *   **Koken**, **Moodle**, **October CMS**：相关 Getshell 或 RCE 命令。
*   **反序列化**：VIEWSTATE.NET 反序列化。
*   **Log4Shell**：相关利用信息。
*   **其他协议漏洞**：
    *   **POP3**: `telnet` 连接，`hydra` 爆破。
    *   **SSH**: 私钥连接，版本兼容性处理，传递参数，`crackmapexec` 爆破。
    *   **WINRM**: `evil-winrm` 连接。
    *   **TFTP**: `tftp` 连接和下载。
    *   **SMTP**: `telnet` 连接，枚举用户。
*   **MDT 漏洞**：定位服务器，获取 BCD/WIM 文件，提取凭证的命令。
*   **PyTorch 模型注入**：使用 `inject.py` 脚本注入恶意代码执行命令。

请输出每个命令，并简要说明其用途。
"""
        
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
                max_tokens=2000
            )
            logger.info("Received response from DeepSeek API.")
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"AI分析过程中出错: {str(e)}")
            return f"AI分析过程中出错: {str(e)}"

analyzer = AutoReconAnalyzer()

# 存储分析结果
analysis_results: Dict[str, Dict] = {}

# 存储扫描状态和日志
scan_status: Dict[str, Dict] = {}

def find_node_in_tree(tree, node_name):
    if tree["name"] == node_name:
        return tree
    if "children" in tree:
        for child in tree["children"]:
            found_node = find_node_in_tree(child, node_name)
            if found_node:
                return found_node
    return None

def parse_nmap_results(results_dir: str) -> Dict:
    """解析Nmap扫描结果"""
    nmap_data = {}
    logger.info(f"Parsing Nmap results from: {results_dir}")
    
    # results_dir 已经是 results/<ip> 这样的路径
    target_ip = os.path.basename(results_dir)
    autorecon_output_base_path = os.path.join(results_dir, target_ip)
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
    """解析漏洞扫描结果"""
    vuln_data = {}
    logger.info(f"Parsing vulnerability data from: {results_dir}")

    # results_dir 已经是 results/<ip> 这样的路径
    target_ip = os.path.basename(results_dir)
    autorecon_output_base_path = os.path.join(results_dir, target_ip)

    # 遍历所有服务目录下的报告文件
    services_report_path = os.path.join(autorecon_output_base_path, 'report', 'report.md', target_ip, 'Services')
    if os.path.exists(services_report_path):
        for service_dir_name in os.listdir(services_report_path):
            service_dir_path = os.path.join(services_report_path, service_dir_name)
            if os.path.isdir(service_dir_path):
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
    """生成网络关系树状图数据"""
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
                            display_name = summary_match.group(1).strip()[:50] + "..."
                        else:
                            display_name = vuln_info["description"].strip()[:50] + "..."
                    elif len(vuln_info["description"]) > 50:
                        display_name = vuln_info["description"].strip()[:50] + "..."
                    
                    # Prepend severity to the display name
                    full_display_name = f"[{vuln_info['severity'].capitalize()}] {display_name}"

                    vuln_node = {
                        "name": full_display_name,
                        "attributes": {
                            "type": "vulnerability",
                            "severity": vuln_info["severity"],
                            "description": vuln_info["description"]
                        }
                    }
                    service_node["children"].append(vuln_node)
        
        tree_data["children"].append(host_node)

    logger.info(f"Generated tree with {len(tree_data['children'])} top-level hosts.")
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

def run_autorecon(ip: str, scan_id: str):
    """在后台运行AutoRecon扫描"""
    try:
        # 创建结果目录，以 IP 为名，autorecon 内部会再创建一层以 IP 为名的子目录
        results_dir = f"results/{ip}"
        os.makedirs(results_dir, exist_ok=True)
        
        # 运行AutoRecon
        process = subprocess.Popen(
            ["autorecon", ip, "-o", results_dir, "--ignore-plugin-checks", "--disable-keyboard-control"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # 将实际的 results_dir 路径存储到 scan_status 中，以便后续获取结果
        scan_status[scan_id]["results_dir"] = results_dir
        
        # 读取输出
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                scan_status[scan_id]["logs"].append(output.strip())
        
        # 检查扫描结果
        if process.returncode == 0:
            scan_status[scan_id]["status"] = "completed"
        else:
            scan_status[scan_id]["status"] = "failed"
            scan_status[scan_id]["error"] = "AutoRecon scan failed"
            
    except Exception as e:
        scan_status[scan_id]["status"] = "failed"
        scan_status[scan_id]["error"] = str(e)

@app.post("/scan")
async def start_scan(request: ScanRequest):
    ip = request.ip
    overwrite = request.overwrite # Get the overwrite flag from the request
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = {"status": "pending", "logs": [], "start_time": datetime.now(), "ip": ip}

    # Define paths
    results_dir = os.path.join("results", ip)
    autorecon_output_dir = os.path.join(results_dir, ip)

    # If overwrite is true, delete the existing results directory
    if overwrite and os.path.exists(results_dir):
        logger.info(f"Overwriting existing results for {ip}. Deleting directory: {results_dir}")
        try:
            shutil.rmtree(results_dir)
            logger.info(f"Successfully deleted {results_dir}")
        except OSError as e:
            logger.error(f"Error deleting directory {results_dir}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to delete existing results: {e}")

    # Create the results directory if it doesn't exist
    os.makedirs(autorecon_output_dir, exist_ok=True)

    # Start AutoRecon in a separate thread
    thread = Thread(target=run_autorecon, args=(ip, scan_id))
    thread.daemon = True
    thread.start()

    return JSONResponse({"message": "Scan initiated", "scan_id": scan_id, "ip": ip})

@app.get("/scan_status/{scan_id}")
async def get_scan_status(scan_id: str):
    logger.info(f"Received request for scan status for scan_id: {scan_id}")
    if scan_id not in scan_status:
        logger.error(f"Scan with scan_id: {scan_id} not found.")
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = scan_status[scan_id]
    all_logs = status["logs"] # 返回所有已累积的日志
    
    logger.info(f"Returning status '{status['status']}' for scan_id: {scan_id}")
    return {
        "status": status["status"],
        "new_logs": all_logs,
        "error": status.get("error")
    }

@app.get("/check_results_exists/{ip}")
async def check_results_exists(ip: str):
    logger.info(f"Received request to check results existence for IP: {ip}")
    # autorecon的输出路径是 results/<ip>/<ip>/...
    autorecon_output_path = Path(f"results/{ip}/{ip}")
    exists = autorecon_output_path.is_dir()
    logger.info(f"Results for IP: {ip} exists: {exists}")
    return {"exists": exists}

@app.get("/load_existing_results/{ip}")
async def load_existing_results(ip: str):
    logger.info(f"Received request to load existing results for IP: {ip}")
    # results_dir 传递给 parse_nmap_results 和 parse_vulnerability_data 的应该是 results/<ip>
    results_root_dir = f"results/{ip}"
    # autorecon的实际输出在 results/<ip>/<ip>
    autorecon_actual_output_dir = os.path.join(results_root_dir, ip)

    if not Path(autorecon_actual_output_dir).is_dir():
        logger.error(f"Results for IP: {ip} not found at {autorecon_actual_output_dir}")
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
    logger.info(f"Received request to analyze scan results for IP: {ip}")
    """自动调用DeepSeek分析AutoRecon扫描结果"""
    results_path = f"results/{ip}/{ip}" # AutoRecon's output path
    
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
    logger.info(f"Received compressed file upload: {file.filename}")
    temp_file_path = Path("temp_compressed") / file.filename
    temp_extract_dir = Path("temp_extracted")

    # Clean up any previous temp directories
    if temp_file_path.parent.exists():
        shutil.rmtree(temp_file_path.parent)
    temp_file_path.parent.mkdir(parents=True, exist_ok=True)

    if temp_extract_dir.exists():
        shutil.rmtree(temp_extract_dir)
    temp_extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Save the uploaded file temporarily
        async with aiofiles.open(temp_file_path, "wb") as out_file:
            while content := await file.read(1024):
                await out_file.write(content)
        logger.info(f"Saved compressed file to: {temp_file_path}")

        # Decompress the file
        if zipfile.is_zipfile(temp_file_path):
            with zipfile.ZipFile(temp_file_path, "r") as zip_ref:
                zip_ref.extractall(temp_extract_dir)
            logger.info(f"Decompressed zip file to: {temp_extract_dir}")
        elif tarfile.is_tarfile(temp_file_path):
            with tarfile.open(temp_file_path, "r") as tar_ref:
                tar_ref.extractall(temp_extract_dir)
            logger.info(f"Decompressed tar file to: {temp_extract_dir}")
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type. Please upload a .zip or .tar.gz file.")

        # Find the actual IP directory inside the extracted content
        # Assumes the extracted content will have a single root directory which is the IP
        extracted_contents = list(temp_extract_dir.iterdir())
        if not extracted_contents or not extracted_contents[0].is_dir():
            raise HTTPException(status_code=400, detail="Extracted content does not contain a single IP directory.")

        ip_dir = extracted_contents[0]
        ip_address = ip_dir.name

        # Move the extracted IP directory to the results directory
        target_results_dir = Path("results") / ip_address

        if target_results_dir.exists():
            logger.info(f"Existing results for {ip_address} found. Overwriting.")
            shutil.rmtree(target_results_dir)
        
        shutil.move(ip_dir, target_results_dir)
        logger.info(f"Moved extracted results to: {target_results_dir}")

        # Process the results (similar to handleLoadExistingResults)
        nmap_data = parse_nmap_results(str(target_results_dir))
        vuln_data = parse_vulnerability_data(str(target_results_dir))
        graph_data = generate_network_graph(nmap_data, vuln_data)

        # Save analysis results and trigger AI analysis (if applicable)
        analysis_id = f"analysis_{ip_address}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        analysis_results[analysis_id] = {
            "nmap_data": nmap_data,
            "vuln_data": vuln_data,
            "graph_data": graph_data,
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S")
        }

        # Trigger AI analysis
        # This will be done by the frontend after getting the graph data

        return JSONResponse({
            "message": "Compressed file uploaded and processed successfully",
            "ip": ip_address,
            "analysis_id": analysis_id,
            "graph_data": graph_data
        })

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error processing compressed file: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to process compressed file: {str(e)}")
    finally:
        # Clean up temporary files and directories
        if temp_file_path.exists():
            os.remove(temp_file_path)
        if temp_extract_dir.exists():
            shutil.rmtree(temp_extract_dir)
        logger.info(f"Cleaned up temporary files: {temp_file_path} and {temp_extract_dir}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 