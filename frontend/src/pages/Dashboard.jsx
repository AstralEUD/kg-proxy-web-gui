import React, { useState, useEffect, useRef } from 'react';
import { Box, Grid, Card, CardContent, Typography, LinearProgress, Chip, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Shield, CloudQueue, Block, Speed, Terminal, CheckCircle, Warning, Error as ErrorIcon, Info } from '@mui/icons-material';
import client from '../api/client';

const eventIcons = {
    success: <CheckCircle sx={{ fontSize: 12, color: '#00c853' }} />,
    warning: <Warning sx={{ fontSize: 12, color: '#ffab00' }} />,
    error: <ErrorIcon sx={{ fontSize: 12, color: '#f50057' }} />,
    info: <Info sx={{ fontSize: 12, color: '#00e5ff' }} />,
};

export default function Dashboard() {
    const [trafficData, setTrafficData] = useState([]);
    const [stats, setStats] = useState({ connections: 0, blocked: 0, origins: 0, cpu: 0, memory: 0, disk: 0 });
    const [events, setEvents] = useState([]);
    const [requiredPorts, setRequiredPorts] = useState([]);
    const [firewallRules, setFirewallRules] = useState('');
    const [mockMode, setMockMode] = useState(true);
    const [wireguardStatus, setWireguardStatus] = useState(null);
    const prevStats = useRef({ allowed: 0, blocked: 0 });

    // Fetch system status from backend
    const fetchStatus = async () => {
        try {
            const res = await client.get('/status');
            const data = res.data;

            setStats({
                connections: data.connections || 0,
                blocked: data.blocked_count || 0,
                origins: data.origins_count || 0,
                cpu: data.cpu_usage || 0,
                memory: data.memory_usage || 0,
                disk: data.disk_usage || 0,
            });
            setEvents(data.events || []);
            setRequiredPorts(data.required_ports || []);
            setMockMode(data.mock_mode);

            // Add traffic data point based on real connection counts
            const now = new Date();
            const timeStr = now.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

            // Calculate delta for chart (simulated PPS based on connection changes)
            const allowedDelta = Math.max(0, (data.connections || 0) - prevStats.current.allowed);
            const blockedDelta = Math.max(0, (data.blocked_count || 0) - prevStats.current.blocked);

            prevStats.current = { allowed: data.connections || 0, blocked: data.blocked_count || 0 };

            setTrafficData(prev => {
                const newPoint = {
                    time: timeStr,
                    allowed: data.connections || allowedDelta,
                    blocked: blockedDelta,
                };
                const updated = [...prev, newPoint];
                return updated.length > 60 ? updated.slice(-60) : updated;
            });

        } catch (e) {
            console.error('Failed to fetch status:', e);
            // Keep existing data on error
        }
    };

    // Fetch firewall rules
    const fetchFirewall = async () => {
        try {
            const res = await client.get('/firewall/status');
            setFirewallRules(res.data.rules || '');
        } catch (e) {
            console.error('Failed to fetch firewall:', e);
        }
    };

    // Fetch WireGuard status
    const fetchWireGuard = async () => {
        try {
            const res = await client.get('/wireguard/status');
            setWireguardStatus(res.data);
        } catch (e) {
            console.error('Failed to fetch WireGuard:', e);
        }
    };

    // Initial fetch and periodic refresh
    useEffect(() => {
        fetchStatus();
        fetchFirewall();
        fetchWireGuard();

        // Refresh every 3 seconds
        const interval = setInterval(() => {
            fetchStatus();
        }, 3000);

        // Refresh firewall and WireGuard every 10 seconds
        const slowInterval = setInterval(() => {
            fetchFirewall();
            fetchWireGuard();
        }, 10000);

        return () => {
            clearInterval(interval);
            clearInterval(slowInterval);
        };
    }, []);

    const StatCard = ({ icon, title, value, gradient }) => (
        <Card sx={{ background: gradient, borderRadius: 2, height: '100%', minHeight: 110 }}>
            <CardContent sx={{ py: 2, px: 3, '&:last-child': { pb: 2 }, display: 'flex', flexDirection: 'column', justifyContent: 'center', height: '100%' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    {icon}
                    <Typography variant="overline" sx={{ ml: 1, opacity: 0.9, fontSize: 11, fontWeight: 'bold' }}>{title}</Typography>
                </Box>
                <Typography variant="h4" sx={{ fontWeight: 'bold', letterSpacing: 1 }}>
                    {typeof value === 'number' ? value.toLocaleString() : value}
                </Typography>
            </CardContent>
        </Card>
    );

    return (
        <Box sx={{ width: '100%' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <Shield sx={{ color: '#00e5ff', mr: 2, fontSize: 32 }} />
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#00e5ff' }}>Command Center</Typography>
                <Chip label={mockMode ? 'MOCK' : 'LIVE'} size="small" sx={{ ml: 2, bgcolor: mockMode ? '#ffab0030' : '#00c85330', color: mockMode ? '#ffab00' : '#00c853', fontWeight: 'bold' }} />
            </Box>

            {/* Row 1: 4 Key Stats */}
            <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard icon={<Speed sx={{ color: '#fff', fontSize: 20 }} />} title="Active Connections" value={stats.connections} gradient="linear-gradient(135deg, #0d47a1, #00e5ff)" />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard icon={<Block sx={{ color: '#fff', fontSize: 20 }} />} title="Threats Blocked" value={stats.blocked} gradient="linear-gradient(135deg, #880e4f, #f50057)" />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard icon={<CloudQueue sx={{ color: '#fff', fontSize: 20 }} />} title="Active Origins" value={stats.origins} gradient="linear-gradient(135deg, #1b5e20, #00c853)" />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard icon={<Shield sx={{ color: '#fff', fontSize: 20 }} />} title="Defense Status" value={mockMode ? "MOCK" : "ACTIVE"} gradient="linear-gradient(135deg, #e65100, #ffab00)" />
                </Grid>
            </Grid>

            {/* Row 2: Live Traffic Monitor (Full Width) */}
            <Card sx={{ bgcolor: '#111', borderRadius: 2, border: '1px solid #1a1a1a', height: 420, mb: 3, mx: 0 }}>
                <CardContent sx={{ p: 3, height: '100%', display: 'flex', flexDirection: 'column' }}>
                    <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between' }}>
                        <Typography variant="h6" sx={{ color: '#eee', fontWeight: 'bold' }}>📊 Live Traffic Monitor</Typography>
                        <Chip label={mockMode ? "Simulated" : "Real-time"} size="small" color={mockMode ? "warning" : "success"} variant="outlined" />
                    </Box>
                    <Box sx={{ flexGrow: 1 }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={trafficData} margin={{ top: 10, right: 0, left: 0, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="allowedG" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#00e5ff" stopOpacity={0.4} /><stop offset="95%" stopColor="#00e5ff" stopOpacity={0} /></linearGradient>
                                    <linearGradient id="blockedG" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#f50057" stopOpacity={0.4} /><stop offset="95%" stopColor="#f50057" stopOpacity={0} /></linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                                <XAxis dataKey="time" stroke="#444" tick={{ fontSize: 10 }} interval="preserveStartEnd" minTickGap={30} />
                                <YAxis stroke="#444" tick={{ fontSize: 11 }} orientation="right" />
                                <Tooltip contentStyle={{ backgroundColor: '#000', border: '1px solid #444', fontSize: 12, borderRadius: 4 }} />
                                <Area type="monotone" dataKey="allowed" stroke="#00e5ff" strokeWidth={3} fill="url(#allowedG)" name="Connections" animationDuration={500} />
                                <Area type="monotone" dataKey="blocked" stroke="#f50057" strokeWidth={3} fill="url(#blockedG)" name="Blocked" animationDuration={500} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </Box>
                </CardContent>
            </Card>

            {/* Row 3: Unified Data Views */}
            <Grid container spacing={3}>
                {/* Left Column: WireGuard Status */}
                <Grid item xs={12} lg={8}>
                    <Card sx={{ bgcolor: '#111', borderRadius: 2, border: '1px solid #1a1a1a', height: '100%', minHeight: 400 }}>
                        <CardContent sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
                            <Typography variant="subtitle1" sx={{ mb: 2, color: '#888' }}>🔒 WireGuard Status</Typography>
                            {wireguardStatus ? (
                                <Box>
                                    <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
                                        <Chip label={`Interface: ${wireguardStatus.interface || 'wg0'}`} size="small" color="primary" variant="outlined" />
                                        <Chip label={`Port: ${wireguardStatus.listen_port || '51820'}`} size="small" color="info" variant="outlined" />
                                        <Chip label={wireguardStatus.is_available ? 'Active' : 'Inactive'} size="small" color={wireguardStatus.is_available ? 'success' : 'error'} />
                                    </Box>
                                    <Typography variant="caption" sx={{ color: '#666', mb: 1, display: 'block' }}>
                                        Public Key: <code style={{ color: '#00e5ff' }}>{wireguardStatus.public_key?.substring(0, 20)}...</code>
                                    </Typography>
                                    <Typography variant="subtitle2" sx={{ mt: 2, mb: 1, color: '#888' }}>Connected Peers ({wireguardStatus.peers?.length || 0})</Typography>
                                    <TableContainer>
                                        <Table size="small">
                                            <TableHead>
                                                <TableRow sx={{ '& th': { bgcolor: '#111', color: '#888', borderColor: '#222' } }}>
                                                    <TableCell>Endpoint</TableCell>
                                                    <TableCell>Allowed IPs</TableCell>
                                                    <TableCell>Last Handshake</TableCell>
                                                    <TableCell>Transfer</TableCell>
                                                </TableRow>
                                            </TableHead>
                                            <TableBody>
                                                {(wireguardStatus.peers || []).map((peer, i) => (
                                                    <TableRow key={i} sx={{ '& td': { borderColor: '#222' } }}>
                                                        <TableCell sx={{ color: '#00e5ff', fontFamily: 'monospace', fontSize: 11 }}>{peer.endpoint || 'N/A'}</TableCell>
                                                        <TableCell sx={{ fontSize: 11 }}>{peer.allowed_ips || 'N/A'}</TableCell>
                                                        <TableCell sx={{ fontSize: 11, color: '#888' }}>{peer.latest_handshake || 'Never'}</TableCell>
                                                        <TableCell sx={{ fontSize: 11 }}>↓{peer.transfer_rx || '0'} ↑{peer.transfer_tx || '0'}</TableCell>
                                                    </TableRow>
                                                ))}
                                                {(!wireguardStatus.peers || wireguardStatus.peers.length === 0) && (
                                                    <TableRow>
                                                        <TableCell colSpan={4} sx={{ color: '#666', textAlign: 'center' }}>No peers connected</TableCell>
                                                    </TableRow>
                                                )}
                                            </TableBody>
                                        </Table>
                                    </TableContainer>
                                </Box>
                            ) : (
                                <Typography sx={{ color: '#666' }}>Loading WireGuard status...</Typography>
                            )}
                        </CardContent>
                    </Card>
                </Grid>

                {/* Right Column: System Status Stack */}
                <Grid item xs={12} lg={4}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>

                        {/* 1. System Resources */}
                        <Card sx={{ bgcolor: '#111', borderRadius: 2, border: '1px solid #1a1a1a' }}>
                            <CardContent sx={{ p: 2 }}>
                                <Typography variant="subtitle2" sx={{ mb: 1.5, color: '#888' }}>💻 System Resources</Typography>
                                {[{ name: 'CPU Usage', val: stats.cpu, color: 'primary' }, { name: 'Memory Usage', val: stats.memory, color: 'success' }, { name: 'Disk Usage', val: stats.disk, color: 'warning' }].map(s => (
                                    <Box key={s.name} sx={{ mb: 1.5 }}>
                                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                                            <Typography variant="caption" sx={{ color: '#ccc' }}>{s.name}</Typography>
                                            <Typography variant="caption" sx={{ color: s.val > 80 ? '#f50057' : '#00e5ff', fontWeight: 'bold' }}>{s.val}%</Typography>
                                        </Box>
                                        <LinearProgress variant="determinate" value={s.val} color={s.color} sx={{ height: 4, borderRadius: 2, bgcolor: '#222' }} />
                                    </Box>
                                ))}
                            </CardContent>
                        </Card>

                        {/* 2. System Events */}
                        <Card sx={{ bgcolor: '#111', borderRadius: 2, border: '1px solid #1a1a1a', height: 250 }}>
                            <CardContent sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
                                <Typography variant="subtitle2" sx={{ mb: 1, color: '#888' }}><Terminal sx={{ fontSize: 14, mr: 0.5, verticalAlign: 'middle' }} />System Events</Typography>
                                <Box sx={{ flexGrow: 1, overflow: 'auto', fontFamily: 'monospace', fontSize: 11 }}>
                                    {events.length === 0 ? (
                                        <Typography variant="caption" sx={{ color: '#666' }}>No events yet</Typography>
                                    ) : events.map((e, i) => (
                                        <Box key={i} sx={{ display: 'flex', alignItems: 'center', py: 0.5, borderBottom: '1px solid #222' }}>
                                            {eventIcons[e.type] || eventIcons.info}
                                            <Typography variant="caption" sx={{ ml: 1, color: '#666', minWidth: 55 }}>{e.time}</Typography>
                                            <Typography variant="caption" sx={{ ml: 1, color: '#ccc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.message}</Typography>
                                        </Box>
                                    ))}
                                </Box>
                            </CardContent>
                        </Card>

                        {/* 3. Active Iptables Rules */}
                        <Card sx={{ bgcolor: '#111', borderRadius: 2, border: '1px solid #1a1a1a', height: 280 }}>
                            <CardContent sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
                                <Typography variant="subtitle2" sx={{ mb: 1, color: '#888' }}>🔥 Active iptables Rules</Typography>
                                <Paper sx={{
                                    bgcolor: '#0a0a0a', p: 1.5, flexGrow: 1, overflow: 'auto',
                                    fontFamily: 'monospace', fontSize: 11, color: '#0f0', border: '1px solid #222',
                                    '&::-webkit-scrollbar': { width: '8px' },
                                    '&::-webkit-scrollbar-track': { background: '#111' },
                                    '&::-webkit-scrollbar-thumb': { background: '#333', borderRadius: '4px' }
                                }}>
                                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{firewallRules || '# Loading iptables rules...'}</pre>
                                </Paper>
                            </CardContent>
                        </Card>

                    </Box>
                </Grid>
            </Grid>
        </Box>
    );
}
