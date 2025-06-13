import React, { useState, useCallback, useRef, useEffect } from 'react';
import axios from 'axios';
import { Tree } from 'react-d3-tree';
import { marked } from 'marked';
import './App.css';

function App() {
  const [file, setFile] = useState(null);
  const [directory, setDirectory] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [treeData, setTreeData] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [annotationText, setAnnotationText] = useState("");
  const [containerHeight, setContainerHeight] = useState(600); // 默认高度
  const [scanIp, setScanIp] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanLogs, setScanLogs] = useState([]);
  const [aiAnalysisReport, setAiAnalysisReport] = useState(""); // New state for AI analysis report
  const [isAnalyzing, setIsAnalyzing] = useState(false); // New state for AI analysis loading
  const [scanLoading, setScanLoading] = useState(false); // New state for scan loading
  const [showOverwriteConfirm, setShowOverwriteConfirm] = useState(false); // New state for overwrite confirmation dialog
  const [ipExistsForOverwrite, setIpExistsForOverwrite] = useState(false); // New state to track if IP exists
  const isResizing = useRef(false);
  const startY = useRef(0);
  const startHeight = useRef(0);
  const logEndRef = useRef(null);

  // IP 地址验证函数
  const isValidIpAddress = (ip) => {
    // 匹配 IPv4 地址的正则表达式
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    // 匹配 IPv6 地址的正则表达式 (简化版，可根据需要扩展)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$/;

    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  };

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
    setError(null);
  };

  const handleUpload = async () => {
    if (!file) {
      setError('Please select a compressed file first');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
      setUploading(true);
      setError(null);
      console.log('Uploading compressed file...');
      
      const response = await axios.post('http://localhost:8000/upload_compressed_results', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      console.log('Upload response:', response.data);
      
      if (response.data.graph_data) {
        console.log('Setting tree data:', response.data.graph_data);
        setTreeData(response.data.graph_data);
        console.log('Final tree data structure:', JSON.stringify(response.data.graph_data, null, 2));

        const uploadedIp = response.data.ip;
        setScanIp(uploadedIp);
        if (uploadedIp) {
          await analyzeScanResults(uploadedIp);
        }

      } else {
        console.error('No tree data in response');
        setError('No tree data received from server');
      }
    } catch (err) {
      console.error('Upload error:', err);
      setError(err.response?.data?.detail || err.message || 'An error occurred during upload');
    } finally {
      setUploading(false);
    }
  };

  const handleNodeClick = useCallback((nodeDatum, evt) => {
    console.log('Node clicked:', nodeDatum);
    setSelectedNode(nodeDatum);
    setAnnotationText(nodeDatum.annotation || "");
  }, []);

  const handleSaveAnnotation = async () => {
    if (!selectedNode || !localStorage.getItem('currentAnalysisId')) {
      setError("No node selected or analysis ID available.");
      return;
    }

    const analysisId = localStorage.getItem('currentAnalysisId');
    const nodeName = selectedNode.name;

    try {
      const response = await axios.post('http://localhost:8000/annotate_node', {
        analysis_id: analysisId,
        parent_node_name: nodeName,
        annotation_text: annotationText
      }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });
      console.log('Annotation saved:', response.data);
      
      // 重新获取更新后的树数据
      const analysisResponse = await axios.get(`http://localhost:8000/analysis/${analysisId}`);
      setTreeData(analysisResponse.data.graph_data);
      setAnnotationText(""); // 清空批注输入框
      setError(null);

    } catch (err) {
      console.error('Error saving annotation:', err);
      const errorMessage = typeof err.response?.data?.detail === 'object'
        ? JSON.stringify(err.response.data.detail)
        : err.response?.data?.detail || err.message || 'Error saving annotation';
      setError(errorMessage);
    }
  };

  const handleDeleteNode = async () => {
    if (!selectedNode || !localStorage.getItem('currentAnalysisId')) {
      setError("No node selected or analysis ID available.");
      return;
    }

    const analysisId = localStorage.getItem('currentAnalysisId');
    const nodeName = selectedNode.name;

    try {
      const response = await axios.post('http://localhost:8000/delete_node', {
        analysis_id: analysisId,
        node_name: nodeName
      }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });
      console.log('Node deleted:', response.data);
      
      // 重新获取更新后的树数据
      const analysisResponse = await axios.get(`http://localhost:8000/analysis/${analysisId}`);
      setTreeData(analysisResponse.data.graph_data);
      setSelectedNode(null); // 清除选中的节点
      setError(null);

    } catch (err) {
      console.error('Error deleting node:', err);
      const errorMessage = typeof err.response?.data?.detail === 'object'
        ? JSON.stringify(err.response.data.detail)
        : err.response?.data?.detail || err.message || 'Error deleting node';
      setError(errorMessage);
    }
  };

  const getNodeColor = (node) => {
    switch (node.attributes?.type) {
      case 'host':
        return '#3498db';
      case 'service':
        return '#2ecc71';
      case 'vulnerability':
        return '#e74c3c';
      case 'annotation':
        return '#f1c40f'; // 黄色表示批注节点
      default:
        return '#95a5a6';
    }
  };

  const renderCustomNodeElement = useCallback(({ nodeDatum, toggleNode }) => {
    const nodeWidth = 180;
    const nodeHeight = 70;
    const rectX = -nodeWidth / 2;
    const rectY = -nodeHeight / 2;

    const nodeColor = getNodeColor(nodeDatum);
    const hasChildren = nodeDatum.children && nodeDatum.children.length > 0;

    let textContent;
    if (nodeDatum.attributes?.type === 'vulnerability') {
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
    } else if (nodeDatum.attributes?.type === 'annotation') {
      const maxTextLength = 30;
      const truncatedText = nodeDatum.attributes.text.length > maxTextLength
        ? nodeDatum.attributes.text.substring(0, maxTextLength) + '...'
        : nodeDatum.attributes.text;

      textContent = (
        <>
          <text fill="black" strokeWidth="0" textAnchor="middle" dominantBaseline="middle" x={0} y={-15} style={{ fontSize: '12px', fontWeight: 'bold' }}>
            {nodeDatum.name}
          </text>
          <text fill="black" strokeWidth="0" textAnchor="middle" dominantBaseline="middle" x={0} y={15} style={{ fontSize: '10px' }}>
            {truncatedText}
          </text>
        </>
      );
    } else {
      // For general nodes (like IP addresses, etc.), ensure full name display
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

    const handleClick = (event) => {
      event.stopPropagation();
      setSelectedNode(nodeDatum);
      setAnnotationText(nodeDatum.annotation || "");
    };

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
          onClick={handleClick}
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
  }, [setSelectedNode, setAnnotationText]);

  const handleMouseDown = (e) => {
    isResizing.current = true;
    startY.current = e.clientY;
    startHeight.current = containerHeight;
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  };

  const handleMouseMove = (e) => {
    if (!isResizing.current) return;
    const deltaY = e.clientY - startY.current;
    const newHeight = Math.max(300, Math.min(800, startHeight.current + deltaY)); // 限制最小和最大高度
    setContainerHeight(newHeight);
  };

  const handleMouseUp = () => {
    isResizing.current = false;
    document.removeEventListener('mousemove', handleMouseMove);
    document.removeEventListener('mouseup', handleMouseUp);
  };

  useEffect(() => {
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  const handleScan = async () => {
    if (!scanIp) {
      setError('Please enter an IP address');
      return;
    }

    if (!isValidIpAddress(scanIp)) {
      setError('Please enter a valid IP address (IPv4 or IPv6)');
      return;
    }

    try {
      setScanning(true);
      setError(null);
      setScanLogs([]);

      // Check if results already exist for the IP
      const existsResponse = await axios.get(`http://localhost:8000/check_results_exists/${scanIp}`);
      const resultsExist = existsResponse.data.exists;

      if (resultsExist) {
        setIpExistsForOverwrite(true);
        setShowOverwriteConfirm(true); // Show confirmation dialog
        setScanLoading(false); // Stop loading indicator while waiting for user input
        return; // Wait for user confirmation
      } else {
        // No existing results, proceed with scan immediately (overwrite is false by default)
        await confirmAndStartScan(false); 
      }

    } catch (err) {
      console.error("Error checking existing results:", err);
      setError(`Error checking existing results: ${err.response?.data?.detail || err.message}`);
      setScanning(false);
      setScanLoading(false);
    }
  };

  const confirmAndStartScan = async (overwrite) => {
    setShowOverwriteConfirm(false); // Hide the dialog
    setScanLoading(true); // Start loading again after confirmation

    try {
      const scanResponse = await axios.post('http://localhost:8000/scan', {
        ip: scanIp,
        overwrite: overwrite // Pass the overwrite flag
      }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });

      console.log('Scan started response:', scanResponse.data);
      const initiatedScanId = scanResponse.data.scan_id; // Capture the scan_id here
      setScanning(true);
      setScanLogs([`Starting scan for ${scanIp}...`]);
      setError(null);

      // Start polling for logs
      const pollingInterval = setInterval(async () => {
        try {
          // Use initiatedScanId for polling status and logs
          const logsResponse = await axios.get(`http://localhost:8000/scan_status/${initiatedScanId}`);
          const logs = logsResponse.data.new_logs; // Backend returns 'new_logs'
          setScanLogs(logs);
          if (logsResponse.data.status === 'completed' || logsResponse.data.status === 'failed') {
            clearInterval(pollingInterval);
            setScanning(false);
            setScanLoading(false); // Scan completed, stop loading
            if (logsResponse.data.status === 'completed') {
              // Load the newly generated results after scan completes using scanId
              const resultsResponse = await axios.get(`http://localhost:8000/scan_results/${initiatedScanId}`);
              if (resultsResponse.data.graph_data) {
                setTreeData(resultsResponse.data.graph_data);
              } else {
                setError('No graph data received after scan completion.');
              }
              // Trigger AI analysis after successful scan using scanIp
              await analyzeScanResults(scanIp);
            } else {
              setError('Scan failed. Check logs for details.');
            }
          }
        } catch (logErr) {
          console.error('Error fetching scan logs:', logErr);
          clearInterval(pollingInterval);
          setScanning(false);
          setScanLoading(false);
          setError(`Error fetching scan logs: ${logErr.message}`);
        }
      }, 2000);

    } catch (err) {
      console.error('Error starting scan:', err);
      setError(err.response?.data?.detail || err.message || 'An error occurred during scan initiation');
      setScanning(false);
      setScanLoading(false);
    }
  };

  const analyzeScanResults = async (ip) => {
    setIsAnalyzing(true); // Set loading to true
    setAiAnalysisReport("正在生成 AI 分析报告，请稍候..."); // Show a temporary message
    try {
      const response = await axios.get(`http://localhost:8000/analyze_scan_results/${ip}`);
      setAiAnalysisReport(response.data.analysis_report);
    } catch (error) {
      console.error("Error fetching AI analysis:", error);
      setAiAnalysisReport(`AI 分析报告生成失败: ${error.message}. 请检查后端日志。`);
    } finally {
      setIsAnalyzing(false); // Set loading to false regardless of success or failure
    }
  };

  const handleLoadExistingResults = async () => {
    setScanLoading(true);
    setTreeData(null);
    setAiAnalysisReport(""); // Clear previous analysis when loading new results
    try {
      const response = await axios.get(`http://localhost:8000/load_existing_results/${scanIp}`);
      setTreeData(response.data.graph_data);
      setScanLogs([]); // Clear logs for existing results
      // Trigger AI analysis after loading existing results
      analyzeScanResults(scanIp);
    } catch (error) {
      console.error("Error loading existing results:", error);
      alert(`加载已有结果失败: ${error.response?.data?.detail || error.message}`);
    } finally {
      setScanLoading(false);
    }
  };

  return (
    <div className="app-container">
      <div className="content-wrapper">
        <div className="sidebar">
          <div className="scan-section">
            <h3>Start New Scan</h3>
            <div className="scan-input">
              <input
                type="text"
                value={scanIp}
                onChange={(e) => setScanIp(e.target.value)}
                placeholder="Enter IP address"
                disabled={scanning}
              />
              <button
                onClick={handleScan}
                disabled={scanning || !scanIp}
              >
                {scanning ? 'Scanning...' : 'Start Scan'}
              </button>
            </div>
            <div className="scan-logs">
              <h4>Scan Logs</h4>
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
        <div className="main-content">
          <div className="upload-section">
            <input
              type="file"
              accept=".zip,.tar.gz"
              onChange={handleFileChange}
              disabled={scanning}
            />
            <button onClick={handleUpload} disabled={!file || uploading || scanning}>
              {uploading ? 'Uploading...' : 'Upload Compressed Results'}
            </button>
          </div>
          {error && <div className="error-message">{error}</div>}
          {scanning && (
            <div className="loading-overlay">
              <div className="loading-spinner"></div>
              <p>正在扫描 {scanIp}...</p>
            </div>
          )}
          {scanLoading && !scanning && (
            <div className="loading-overlay">
              <div className="loading-spinner"></div>
              <p>正在检查现有结果或加载中...</p>
            </div>
          )}
          {isAnalyzing && (
            <div className="loading-overlay">
              <div className="loading-spinner"></div>
              <p>正在生成 AI 分析报告，请稍候...</p>
            </div>
          )}
          {showOverwriteConfirm && (
            <div className="modal-overlay">
              <div className="modal-content">
                <h2>确认覆盖</h2>
                <p>IP地址 <strong>{scanIp}</strong> 已存在扫描结果。您确定要覆盖吗？</p>
                <div className="modal-actions">
                  <button onClick={() => confirmAndStartScan(true)}>覆盖并重新扫描</button>
                  <button onClick={async () => {
                    setShowOverwriteConfirm(false); // 隐藏弹窗
                    setScanning(false); // 确保扫描状态为false，立即停止"Scanning..."显示
                    setScanLoading(false); // 确保所有与扫描相关的加载状态都停止
                    setError(null); // 清除所有错误信息
                    setScanLogs([]); // 清除扫描日志

                    // 尝试加载现有结果
                    try {
                      await handleLoadExistingResults(); // 它会从state中读取scanIp，无需作为参数传递
                      alert(`已加载 ${scanIp} 的现有结果。`);
                    } catch (loadErr) {
                      console.error("Error loading existing results on cancel:", loadErr);
                      setError(`加载现有结果失败: ${loadErr.response?.data?.detail || loadErr.message}`);
                    }
                  }}>取消</button>
                </div>
              </div>
            </div>
          )}
          <div className="tree-container" style={{ height: `${containerHeight}px` }}>
            {treeData && (
              <Tree
                data={treeData}
                orientation="horizontal"
                pathFunc="step"
                separation={{ siblings: 0.5, nonSiblings: 3.5 }}
                translate={{ x: 100, y: containerHeight / 2 }}
                nodeSize={{ x: 300, y: 150 }}
                renderCustomNodeElement={renderCustomNodeElement}
                onNodeClick={handleNodeClick}
                collapsible={true}
                initialDepth={1}
                zoomable={true}
                draggable={false}
                shouldCollapseNeighborNodes={true}
                rootNodeClassName="root-node"
                branchNodeClassName="branch-node"
                leafNodeClassName="leaf-node"
                pathClassFunc={() => "tree-link"}
                // REMOVED: expanded={Array.from(expandedNodes)}
              />
            )}
          </div>
          <div
            className="resize-handle"
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
          />
        </div>
        <div className="ai-analysis-container">
          <h3>DeepSeek AI 分析报告</h3>
          <div className="ai-analysis-content">
            {isAnalyzing ? (
              <p className="loading-message">正在生成 AI 分析报告，请稍候...</p>
            ) : (
              aiAnalysisReport ? (
                <div dangerouslySetInnerHTML={{ __html: marked.parse(aiAnalysisReport) }} />
              ) : (
                <p>AI 分析报告将在此处显示。</p>
              )
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
