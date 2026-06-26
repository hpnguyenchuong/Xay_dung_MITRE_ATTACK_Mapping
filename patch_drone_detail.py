import re
with open('templates/DroneLifecyclePanel.html', 'r', encoding='utf-8') as f:
    content = f.read()

start_idx = content.find('const renderDetailView = () => {')
end_idx = content.find("return viewMode === 'grid' ? renderGridView() : renderDetailView();")

if start_idx != -1 and end_idx != -1:
    new_render_detail_view = """const renderSegmentedBar = (value, isThreat = false) => {
        const segments = 10;
        const filled = Math.round((value / 100) * segments);
        let colorClass = isThreat 
            ? (value >= 80 ? 'bg-rose-500' : value >= 40 ? 'bg-amber-500' : 'bg-emerald-500')
            : (value <= 20 ? 'bg-rose-500' : value <= 50 ? 'bg-amber-500' : 'bg-emerald-500');
            
        return (
            <div className="flex gap-1">
                {Array.from({ length: segments }).map((_, i) => (
                    <div key={i} className={`h-2.5 w-4 rounded-sm ${i < filled ? colorClass : 'bg-slate-700/50'}`} 
                         style={i < filled ? { boxShadow: '0 0 8px currentColor' } : {}}></div>
                ))}
            </div>
        );
    };

    const renderDetailView = () => {
        const d = drones.find(dr => dr.drone_id === selectedDroneId) || {};
        const sInfo = getStatusInfo(d.status);
        const hasHistoryData = droneDetail && droneDetail.telemetry_history && droneDetail.telemetry_history.length > 1;

        return (
            <div className="absolute inset-0 z-50 bg-slate-950 flex flex-col w-full h-full animate-slide-in-fade">
                {/* Header Fullscreen Overlay */}
                <div className="p-4 shrink-0 flex justify-between items-center bg-[#0f172a] border-b border-slate-800">
                    <button onClick={() => setViewMode('grid')} className="px-4 py-2 bg-slate-800/80 hover:bg-slate-700 text-sky-400 rounded-sm font-mono text-sm border border-slate-700 transition-colors flex items-center gap-2">
                        <span>◀</span> Quay lại Danh sách
                    </button>
                    <div className="font-bold text-xl font-mono text-white flex items-center gap-2">
                        🚁 {selectedDroneId} <span className="text-slate-500 text-sm tracking-widest ml-2">- TACTICAL COMMAND CENTER</span>
                    </div>
                    <button onClick={exportCSV} className="px-4 py-2 bg-emerald-900/40 hover:bg-emerald-800/60 text-emerald-400 border border-emerald-700/50 rounded-sm font-mono text-sm transition-colors flex items-center gap-2">
                        📄 Export Report
                    </button>
                </div>

                <div className="flex-1 overflow-y-auto custom-scrollbar p-4 flex flex-col gap-4">
                    {/* Top Row: Specs & Charts */}
                    <div className="flex flex-col lg:flex-row gap-4 min-h-[340px]">
                        {/* Tactical Specs */}
                        <div className="panel flex-[0.8] p-5 border-slate-800 bg-slate-900/80 backdrop-blur shadow-xl relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-sky-500 to-indigo-500 opacity-50"></div>
                            <div className="text-sm font-bold text-slate-300 mb-5 border-b border-slate-700/50 pb-2 flex items-center gap-2 tracking-widest uppercase">
                                📊 Thông Số Chiến Thuật
                            </div>
                            <div className="flex flex-col gap-5 font-mono text-sm">
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-400">Trạng thái:</span> 
                                    <span style={{ color: sInfo.color, textShadow: `0 0 10px ${sInfo.color}80` }} className="font-bold flex items-center gap-2">
                                        {sInfo.icon} {d.status}
                                    </span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-400">Pin: {d.battery}%</span>
                                    {renderSegmentedBar(d.battery, false)}
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-400">Threat: {d.threat_score}/100</span>
                                    {renderSegmentedBar(d.threat_score, true)}
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-400">Tín hiệu:</span> 
                                    <span className="text-sky-400 font-bold">{d.signal_strength || -52} dBm</span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-400">Nhiệt độ:</span> 
                                    <span className="text-amber-400 font-bold">{d.temp || 45}°C</span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-400">Vệ tinh:</span> 
                                    <span className="text-slate-200 font-bold">{d.satellites || 12}/12</span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-400">Artifacts:</span> 
                                    <span className="text-rose-400 font-bold">{droneDetail?.artifacts?.length || 0}</span>
                                </div>
                            </div>
                        </div>

                        {/* Telemetry Charts */}
                        <div className="flex-[2.2] flex flex-col md:flex-row gap-4">
                            <div className="panel flex-1 p-4 border-slate-800 bg-slate-900/80 backdrop-blur shadow-xl relative">
                                <div className="absolute top-0 left-0 w-1 h-full bg-sky-500/50"></div>
                                <div className="text-xs font-bold text-slate-400 mb-2 uppercase tracking-widest">📈 Telemetry - Altitude & Speed</div>
                                <div className="relative w-full h-[220px]">
                                    {hasHistoryData ? <canvas ref={chart1Ref}></canvas> : <div className="text-slate-600 text-center text-xs mt-10">Đang tải dữ liệu...</div>}
                                </div>
                            </div>
                            <div className="panel flex-1 p-4 border-slate-800 bg-slate-900/80 backdrop-blur shadow-xl relative">
                                <div className="absolute top-0 left-0 w-1 h-full bg-amber-500/50"></div>
                                <div className="text-xs font-bold text-slate-400 mb-2 uppercase tracking-widest">📈 Threat & Battery Trend</div>
                                <div className="relative w-full h-[220px]">
                                    {hasHistoryData ? <canvas ref={chart2Ref}></canvas> : <div className="text-slate-600 text-center text-xs mt-10">Đang tải dữ liệu...</div>}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Deep Analysis & Timeline */}
                    <div className="flex flex-col lg:flex-row gap-4 flex-1">
                        {/* Artifacts Table */}
                        <div className="panel flex-[1.6] p-5 border-slate-800 bg-slate-900/80 backdrop-blur shadow-xl relative">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-rose-500 to-orange-500 opacity-50"></div>
                            <div className="text-sm font-bold text-slate-300 mb-4 border-b border-slate-700/50 pb-2 tracking-widest uppercase">
                                🧬 Phân Tích Sâu (Artifacts & MITRE Mapping)
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-left font-mono text-xs text-slate-300">
                                    <thead className="bg-slate-800/50 text-slate-400">
                                        <tr>
                                            <th className="p-2 border-b border-slate-700">📌 Artifact</th>
                                            <th className="p-2 border-b border-slate-700">Loại</th>
                                            <th className="p-2 border-b border-slate-700">Độ tin cậy</th>
                                            <th className="p-2 border-b border-slate-700">MITRE Technique</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {(droneDetail?.artifacts || []).map((art, idx) => (
                                            <tr key={idx} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                                                <td className="p-2 font-bold text-rose-400">{art.finding}</td>
                                                <td className="p-2 text-sky-300">{art.type || 'System'}</td>
                                                <td className="p-2">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                                                            <div className="h-full bg-emerald-500" style={{width: art.confidence ? (art.confidence*100) + '%' : '90%'}}></div>
                                                        </div>
                                                        <span className="text-[10px] text-slate-400">{art.confidence ? (art.confidence*100).toFixed(0) + '%' : '90%'}</span>
                                                    </div>
                                                </td>
                                                <td className="p-2 text-amber-400">🎯 {art.technique || 'T1071 - Application Layer Protocol'}</td>
                                            </tr>
                                        ))}
                                        {(!droneDetail || droneDetail.artifacts.length === 0) && (
                                            <tr><td colSpan="4" className="p-4 text-center text-slate-500 italic">No artifacts detected.</td></tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        {/* Timeline */}
                        <div className="panel flex-[1.0] p-5 border-slate-800 bg-slate-900/80 backdrop-blur shadow-xl relative min-h-[300px] flex flex-col">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-500 to-sky-500 opacity-50"></div>
                            <div className="text-sm font-bold text-slate-300 mb-4 border-b border-slate-700/50 pb-2 tracking-widest uppercase">
                                🗺️ Lộ Trình Hoạt Động
                            </div>
                            <div className="flex-1 overflow-y-auto custom-scrollbar pr-2">
                                {droneDetail && [...(droneDetail.timeline || []), ...(droneDetail.attacks || [])].sort((a, b) => {
                                    const timeA = a.time || a.started_at || a.timestamp;
                                    const timeB = b.time || b.started_at || b.timestamp;
                                    return new Date(timeA) - new Date(timeB);
                                }).map((ev, i) => {
                                    const isError = ev.attack_type || (ev.artifact && ev.artifact !== 'CLEAN');
                                    const isWarning = ev.stage === 'BEACONING';
                                    const colorCls = isError ? 'text-rose-400' : (isWarning ? 'text-amber-400' : 'text-emerald-400');
                                    const icon = isError ? '🔴' : (isWarning ? '🟡' : '🟢');
                                    
                                    return (
                                        <div key={i} className="flex gap-3 mb-3 border-l border-slate-700 pl-3 relative font-mono text-xs">
                                            <div className="absolute -left-[5px] top-1 text-[8px] bg-slate-900 rounded-full">{icon}</div>
                                            <div className="text-slate-500 shrink-0">[{ev.time || (ev.started_at ? ev.started_at.split(' ')[1] : '')}]</div>
                                            <div className={`flex-1 ${colorCls}`}>
                                                {ev.attack_type ? `🚨 Lệnh ${ev.attack_type} được thực thi` : 
                                                    (ev.artifact ? `Phát hiện: ${ev.artifact}` : `Đăng ký ${ev.stage || 'NORMAL'} drone`)}
                                            </div>
                                        </div>
                                    )
                                })}
                                {(!droneDetail || (droneDetail.timeline.length === 0 && droneDetail.attacks.length === 0)) && (
                                    <div className="text-slate-500 text-center italic text-xs mt-10">Chưa có sự kiện nào được ghi nhận.</div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        );
    };

"""
    content = content[:start_idx] + new_render_detail_view + content[end_idx:]
    with open('templates/DroneLifecyclePanel.html', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Patched successfully!")
else:
    print("Could not find replacement indices.")
