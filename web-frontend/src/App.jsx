/**
 * PenRecon - 渗透测试自动化平台前端应用
 * 
 * 这个文件实现了PenRecon平台的前端用户界面，主要功能包括：
 * 1. 扫描管理 - 启动、监控、查看扫描结果
 * 2. 结果可视化 - 网络拓扑图显示
 * 3. AI分析报告 - 显示AI生成的渗透测试建议
 * 4. 文件上传 - 支持压缩文件上传
 * 5. 实时日志 - 显示扫描进度和日志
 * 
 * 技术栈：
 * - React 18 (函数式组件 + Hooks)
 * - react-d3-tree (网络拓扑图可视化)
 * - Axios (HTTP请求)
 * - Marked (Markdown渲染)
 * 
 * 作者: PenRecon Team
 * 版本: 1.0.0
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import axios from 'axios';
import { Tree } from 'react-d3-tree';
import { marked } from 'marked';
import './App.css';

/**
 * 主应用组件
 * 
 * 提供完整的PenRecon平台用户界面，包括扫描控制、结果展示、AI分析等功能
 */
function App() {
  // ============================================================================
  // 状态管理
  // ============================================================================
  
  // 文件上传相关状态
  const [file, setFile] = useState(null);  // 选择的文件
  const [directory, setDirectory] = useState(null);  // 目录信息
  const [uploading, setUploading] = useState(false);  // 上传状态
  
  // 错误处理状态
  const [error, setError] = useState(null);  // 错误信息
  
  // 数据展示状态
  const [treeData, setTreeData] = useState(null);  // 网络拓扑图数据
  const [containerHeight, setContainerHeight] = useState(600);  // 容器高度
  
  // 扫描相关状态
  const [scanIp, setScanIp] = useState("");  // 扫描目标IP
  const [scanning, setScanning] = useState(false);  // 扫描进行状态
  const [scanLogs, setScanLogs] = useState([]);  // 扫描日志
  const [scanLoading, setScanLoading] = useState(false);  // 扫描加载状态
  
  // 覆盖确认对话框状态
  const [showOverwriteConfirm, setShowOverwriteConfirm] = useState(false);
  const [ipExistsForOverwrite, setIpExistsForOverwrite] = useState(false);
  
  // AI分析相关状态
  const [aiAnalysisReport, setAiAnalysisReport] = useState("");  // AI分析报告
  const [isAnalyzing, setIsAnalyzing] = useState(false);  // AI分析状态
  
  // 拖拽调整相关状态
  const isResizing = useRef(false);
  const startY = useRef(0);
  const startHeight = useRef(0);
  const logEndRef = useRef(null);  // 日志容器底部引用

  // ============================================================================
  // 工具函数
  // ============================================================================
  
  /**
   * IP地址验证函数
   * 
   * 验证输入的IP地址是否为有效的IPv4或IPv6地址
   * 
   * @param {string} ip - 要验证的IP地址
   * @returns {boolean} - 是否为有效IP地址
   */
  const isValidIpAddress = (ip) => {
    // 匹配 IPv4 地址的正则表达式
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    // 匹配 IPv6 地址的正则表达式 (简化版，可根据需要扩展)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$/;

    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  };

  // ============================================================================
  // 事件处理函数
  // ============================================================================
  
  /**
   * 文件选择处理函数
   * 
   * @param {Event} event - 文件选择事件
   */
  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
    setError(null);
  };

  /**
   * 文件上传处理函数
   * 
   * 上传压缩的AutoRecon结果文件，解析并显示结果
   */
  const handleUpload = async () => {
    if (!file) {
      setError('请先选择一个压缩文件');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
      setUploading(true);
      setError(null);
      console.log('正在上传压缩文件...');
      
      const response = await axios.post('http://localhost:8000/upload_compressed_results', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      console.log('上传响应:', response.data);
      
      if (response.data.graph_data) {
        console.log('设置拓扑图数据:', response.data.graph_data);
        setTreeData(response.data.graph_data);
        console.log('最终拓扑图数据结构:', JSON.stringify(response.data.graph_data, null, 2));

        const uploadedIp = response.data.ip;
        setScanIp(uploadedIp);
        if (uploadedIp) {
          await analyzeScanResults(uploadedIp);
        }

      } else {
        console.error('响应中没有拓扑图数据');
        setError('服务器未返回拓扑图数据');
      }
    } catch (err) {
      console.error('上传错误:', err);
      setError(err.response?.data?.detail || err.message || '上传过程中发生错误');
    } finally {
      setUploading(false);
    }
  };

  /**
   * 节点点击处理函数
   * 
   * @param {Object} nodeDatum - 节点数据
   * @param {Event} evt - 点击事件
   */
  const handleNodeClick = useCallback((nodeDatum, evt) => {
    console.log('Node clicked:', nodeDatum);
  }, []);

  // ============================================================================
  // 可视化相关函数
  // ============================================================================
  
  /**
   * 获取节点颜色
   * 
   * 根据节点类型返回对应的颜色
   * 
   * @param {Object} node - 节点对象
   * @returns {string} - 颜色值
   */
  const getNodeColor = (node) => {
    switch (node.attributes?.type) {
      case 'host':
        return '#3498db';  // 蓝色 - 主机节点
      case 'service':
        return '#2ecc71';  // 绿色 - 服务节点
      case 'vulnerability':
        return '#e74c3c';  // 红色 - 漏洞节点
      default:
        return '#95a5a6';  // 灰色 - 默认节点
    }
  };

  /**
   * 自定义节点渲染函数
   * 
   * 为不同类型的节点提供自定义的视觉样式
   * 
   * @param {Object} props - 渲染属性
   * @returns {JSX.Element} - 自定义节点元素
   */
  const renderCustomNodeElement = useCallback(({ nodeDatum, toggleNode }) => {
    const nodeWidth = 180;
    const nodeHeight = 70;
    const rectX = -nodeWidth / 2;
    const rectY = -nodeHeight / 2;

    const nodeColor = getNodeColor(nodeDatum);
    const hasChildren = nodeDatum.children && nodeDatum.children.length > 0;

    let textContent;
    if (nodeDatum.attributes?.type === 'vulnerability') {
      // 漏洞节点的特殊显示
      const maxDescLength = 25;
      const truncatedDesc = nodeDatum.attributes.description.length > maxDescLength
        ? nodeDatum.attributes.description.substring(0, maxDescLength) + '...'
        : nodeDatum.attributes.description;

      textContent = (
        <>
          <text fill="black" strokeWidth="0" textAnchor="middle" dominantBaseline="middle" x={0} y={-15} style={{ fontSize: '12px', fontWeight: 'bold' }}>
            {nodeDatum.name}
          </text>
          <text fill="black" strokeWidth="0" textAnchor="middle" dominantBaseline="middle" x={0} y={0} style={{ fontSize: '10px' }}>
            Severity: {nodeDatum.attributes.severity}
          </text>
          <text fill="black" strokeWidth="0" textAnchor="middle" dominantBaseline="middle" x={0} y={15} style={{ fontSize: '10px' }}>
            {truncatedDesc}
          </text>
        </>
      );
    } else {
      // 一般节点的显示
      textContent = (
        <text
          fill="black"
          strokeWidth="0"
          textAnchor="middle"
          dominantBaseline="middle"
          style={{ fontSize: '12px' }}
        >
          {nodeDatum.name}
        </text>
      );
    }

    return (
      <g>
        <rect
          width={nodeWidth}
          height={nodeHeight}
          x={rectX}
          y={rectY}
          fill={nodeColor}
          stroke="black"
          strokeWidth="1"
          rx="5"
          ry="5"
        />
        {textContent}
        {hasChildren && (
          <circle
            r={15}
            cx={nodeWidth / 2 - 10}
            cy={0}
            fill="lightgray"
            stroke="black"
            strokeWidth="1"
            onClick={(event) => {
              event.stopPropagation();
              toggleNode();
            }}
          />
        )}
      </g>
    );
  }, []);

  // ============================================================================
  // 拖拽调整功能
  // ============================================================================
  
  /**
   * 鼠标按下事件处理
   * 
   * @param {MouseEvent} e - 鼠标事件
   */
  const handleMouseDown = (e) => {
    isResizing.current = true;
    startY.current = e.clientY;
    startHeight.current = containerHeight;
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  };

  /**
   * 鼠标移动事件处理
   * 
   * @param {MouseEvent} e - 鼠标事件
   */
  const handleMouseMove = (e) => {
    if (!isResizing.current) return;
    const deltaY = e.clientY - startY.current;
    const newHeight = Math.max(300, Math.min(800, startHeight.current + deltaY)); // 限制最小和最大高度
    setContainerHeight(newHeight);
  };

  /**
   * 鼠标释放事件处理
   */
  const handleMouseUp = () => {
    isResizing.current = false;
    document.removeEventListener('mousemove', handleMouseMove);
    document.removeEventListener('mouseup', handleMouseUp);
  };

  // 清理事件监听器
  useEffect(() => {
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  // ============================================================================
  // 扫描管理函数
  // ============================================================================
  
  /**
   * 扫描处理函数
   * 
   * 启动新的扫描任务，包括检查现有结果、显示覆盖确认等
   */
  const handleScan = async () => {
    if (!scanIp) {
      setError('请输入IP地址');
      return;
    }

    if (!isValidIpAddress(scanIp)) {
      setError('请输入有效的IP地址（IPv4或IPv6）');
      return;
    }

    try {
      setScanning(true);
      setError(null);
      setScanLogs([]);

      // 检查是否已存在该IP的扫描结果
      const existsResponse = await axios.get(`http://localhost:8000/check_results_exists/${scanIp}`);
      const resultsExist = existsResponse.data.exists;

      if (resultsExist) {
        setIpExistsForOverwrite(true);
        setShowOverwriteConfirm(true); // 显示确认对话框
        setScanLoading(false); // 停止加载指示器，等待用户输入
        return; // 等待用户确认
      } else {
        // 没有现有结果，直接开始扫描（默认不覆盖）
        await confirmAndStartScan(false); 
      }

    } catch (err) {
      console.error("检查现有结果时出错:", err);
      setError(`检查现有结果时出错: ${err.response?.data?.detail || err.message}`);
      setScanning(false);
      setScanLoading(false);
    }
  };

  /**
   * 确认并开始扫描
   * 
   * @param {boolean} overwrite - 是否覆盖现有结果
   */
  const confirmAndStartScan = async (overwrite) => {
    setShowOverwriteConfirm(false); // 隐藏对话框
    setScanLoading(true); // 确认后重新开始加载

    try {
      const scanResponse = await axios.post('http://localhost:8000/scan', {
        ip: scanIp,
        overwrite: overwrite // 传递覆盖标志
      }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });

      console.log('扫描启动响应:', scanResponse.data);
      const initiatedScanId = scanResponse.data.scan_id; // 捕获scan_id
      
      // 检查scan_id是否为null（表示结果已存在且未选择覆盖）
      if (!initiatedScanId) {
        setScanning(false);
        setScanLoading(false);
        setScanLogs([`IP地址 ${scanIp} 的扫描结果已存在。使用覆盖选项重新扫描。`]);
        // 加载现有结果
        await handleLoadExistingResults();
        return;
      }
      
      setScanning(true);
      setScanLogs([`正在开始扫描 ${scanIp}...`]);
      setError(null);

      // 开始轮询日志
      const pollingInterval = setInterval(async () => {
        try {
          // 使用initiatedScanId轮询状态和日志
          const logsResponse = await axios.get(`http://localhost:8000/scan_status/${initiatedScanId}`);
          const logs = logsResponse.data.new_logs; // 后端返回'new_logs'
          setScanLogs(logs);
          if (logsResponse.data.status === 'completed' || logsResponse.data.status === 'failed') {
            clearInterval(pollingInterval);
            setScanning(false);
            setScanLoading(false); // 扫描完成，停止加载
            if (logsResponse.data.status === 'completed') {
              // 扫描完成后加载新生成的结果
              try {
                const resultsResponse = await axios.get(`http://localhost:8000/scan_results/${initiatedScanId}`);
                if (resultsResponse.data.graph_data) {
                  setTreeData(resultsResponse.data.graph_data);
                  console.log('扫描完成后更新拓扑图数据:', resultsResponse.data.graph_data);
                } else {
                  setError('扫描完成后未收到拓扑图数据。');
                }
                // 扫描成功后触发AI分析
                await analyzeScanResults(scanIp);
              } catch (resultsErr) {
                console.error('获取扫描结果时出错:', resultsErr);
                setError(`获取扫描结果时出错: ${resultsErr.response?.data?.detail || resultsErr.message}`);
                // 回退：尝试通过IP加载现有结果
                try {
                  await handleLoadExistingResults();
                } catch (fallbackErr) {
                  console.error('回退加载也失败了:', fallbackErr);
                }
              }
            } else {
              setError('扫描失败。请查看日志了解详情。');
            }
          }
        } catch (logErr) {
          console.error('获取扫描日志时出错:', logErr);
          clearInterval(pollingInterval);
          setScanning(false);
          setScanLoading(false);
          setError(`获取扫描日志时出错: ${logErr.message}`);
        }
      }, 2000);

    } catch (err) {
      console.error('启动扫描时出错:', err);
      setError(err.response?.data?.detail || err.message || '启动扫描过程中发生错误');
      setScanning(false);
      setScanLoading(false);
    }
  };

  /**
   * AI分析扫描结果
   * 
   * @param {string} ip - 目标IP地址
   */
  const analyzeScanResults = async (ip) => {
    setIsAnalyzing(true); // 设置加载状态
    setAiAnalysisReport("正在生成 AI 分析报告，请稍候..."); // 显示临时消息
    try {
      const response = await axios.get(`http://localhost:8000/analyze_scan_results/${ip}`);
      setAiAnalysisReport(response.data.analysis_report);
    } catch (error) {
      console.error("获取AI分析时出错:", error);
      setAiAnalysisReport(`AI 分析报告生成失败: ${error.message}. 请检查后端日志。`);
    } finally {
      setIsAnalyzing(false); // 无论成功失败都设置加载状态为false
    }
  };

  /**
   * 加载现有扫描结果
   * 
   * 加载已存在的扫描结果并显示
   */
  const handleLoadExistingResults = async () => {
    setScanLoading(true);
    setTreeData(null);
    setAiAnalysisReport(""); // 加载新结果时清除之前的分析
    try {
      const response = await axios.get(`http://localhost:8000/load_existing_results/${scanIp}`);
      setTreeData(response.data.graph_data);
      setScanLogs([]); // 清除现有结果的日志
      // 加载现有结果后触发AI分析
      analyzeScanResults(scanIp);
    } catch (error) {
      console.error("加载现有结果时出错:", error);
      alert(`加载已有结果失败: ${error.response?.data?.detail || error.message}`);
    } finally {
      setScanLoading(false);
    }
  };

  // ============================================================================
  // 渲染函数
  // ============================================================================
  
  return (
    <div className="app-container">
      <div className="content-wrapper">
        {/* 侧边栏 - 扫描控制区域 */}
        <div className="sidebar">
          <div className="scan-section">
            <h3>开始新扫描</h3>
            <div className="scan-input">
              <input
                type="text"
                value={scanIp}
                onChange={(e) => setScanIp(e.target.value)}
                placeholder="请输入IP地址"
                disabled={scanning}
              />
              <button
                onClick={handleScan}
                disabled={scanning || !scanIp}
              >
                {scanning ? '扫描中...' : '开始扫描'}
              </button>
            </div>
            <div className="scan-logs">
              <h4>扫描日志</h4>
              <div className="logs-container">
                {scanLogs.map((log, index) => (
                  <div key={index} className="log-entry">
                    {log}
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
            </div>
          </div>
        </div>
        
        {/* 主内容区域 */}
        <div className="main-content">
          {/* 文件上传区域 */}
          <div className="upload-section">
            <input
              type="file"
              accept=".zip,.tar.gz"
              onChange={handleFileChange}
              disabled={scanning}
            />
            <button onClick={handleUpload} disabled={!file || uploading || scanning}>
              {uploading ? '上传中...' : '上传压缩结果文件'}
            </button>
          </div>
          
          {/* 错误信息显示 */}
          {error && <div className="error-message">{error}</div>}
          
          {/* 扫描加载覆盖层 */}
          {scanning && (
            <div className="loading-overlay">
              <div className="loading-spinner"></div>
              <p>正在扫描中...</p>
            </div>
          )}
          
          {/* 网络拓扑图显示区域 */}
          {treeData && (
            <div className="tree-container" style={{ height: `${containerHeight}px` }}>
              <Tree
                data={treeData}
                orientation="vertical"
                pathFunc="step"
                translate={{ x: 400, y: 50 }}
                nodeSize={{ x: 200, y: 100 }}
                separation={{ siblings: 2, nonSiblings: 2.5 }}
                renderCustomNodeElement={renderCustomNodeElement}
                onNodeClick={handleNodeClick}
              />
            </div>
          )}
          
          {/* 高度调整手柄 */}
          {treeData && (
            <div
              className="resize-handle"
              onMouseDown={handleMouseDown}
              style={{ cursor: 'ns-resize' }}
            >
              ⋮⋮
            </div>
          )}
          
          {/* AI分析报告区域 */}
          {aiAnalysisReport && (
            <div className="analysis-section">
              <h3>AI 分析报告</h3>
              {isAnalyzing ? (
                <div className="loading-analysis">
                  <div className="loading-spinner"></div>
                  <p>正在生成 AI 分析报告...</p>
                </div>
              ) : (
                <div 
                  className="analysis-content"
                  dangerouslySetInnerHTML={{ __html: marked(aiAnalysisReport) }}
                />
              )}
            </div>
          )}
        </div>
      </div>
      
      {/* 覆盖确认对话框 */}
      {showOverwriteConfirm && (
        <div className="overlay">
          <div className="confirm-dialog">
            <h3>结果已存在</h3>
            <p>IP地址 {scanIp} 的扫描结果已存在。您是否要覆盖它们？</p>
            <div className="dialog-buttons">
              <button onClick={() => confirmAndStartScan(true)}>覆盖</button>
              <button onClick={() => confirmAndStartScan(false)}>保留现有</button>
              <button onClick={() => setShowOverwriteConfirm(false)}>取消</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
