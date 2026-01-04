import React, { useState, useEffect } from 'react';
import { Box, Grid, Card, CardContent, Typography, LinearProgress, Chip, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Shield, CloudQueue, Block, Speed, Terminal, Lan, CheckCircle, Warning, Error as ErrorIcon, Info } from '@mui/icons-material';
import client from '../api/client';

const generateData = () => {
    const now = new Date();
    return Array.from({ length: 60 }, (_, i) => ({
        time: new Date(now - (59 - i) * 2000).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        allowed: Math.floor(Math.random() * 500) + 200,
        blocked: Math.floor(Math.random() * 100) + 10,
    }));
};

const generateIPTraffic = () => [
    { ip: '121.134.56.78', country: 'KR', pps: 245, status: 'allowed', lastSeen: '2s ago' },
    { ip: '45.33.32.156', country: 'US', pps: 1520, status: 'blocked', lastSeen: '1s ago' },
    { ip: '203.247.51.82', country: 'KR', pps: 189, status: 'allowed', lastSeen: '5s ago' },
    { ip: '185.220.101.45', country: 'DE', pps: 890, status: 'blocked', lastSeen: '3s ago' },
    { ip: '118.235.89.21', country: 'JP', pps: 156, status: 'allowed', lastSeen: '8s ago' },
    { ip: '91.132.147.89', country: 'RU', pps: 2100, status: 'blocked', lastSeen: '1s ago' },
];

const eventIcons = {
    success: <CheckCircle sx={{ fontSize: 12, color: '#00c853' }} />,
    warning: <Warning sx={{ fontSize: 12, color: '#ffab00' }} />,
    error: <ErrorIcon sx={{ fontSize: 12, color: '#f50057' }} />,
    info: <Info sx={{ fontSize: 12, color: '#00e5ff' }} />,
};

export default function Dashboard() {
    const [data, setData] = useState(generateData());
    const [stats, setStats] = useState({ connections: 1245, blocked: 8958, origins: 3, cpu: 45, memory: 62, disk: 35, network: 128 });
    const [events, setEvents] = useState([]);
    const [ipTraffic, setIpTraffic] = useState(generateIPTraffic());
    const [requiredPorts, setRequiredPorts] = useState([]);
    const [firewallRules, setFirewallRules] = useState('');
    const [mockMode, setMockMode] = useState(true);

    useEffect(() => {
        const fetchStatus = async () => {
            try {
                const res = await client.get('/status');
                setStats(s => ({ ...s, connections: res.data.connections || s.connections, cpu: res.data.cpu_usage || s.cpu, memory: res.data.memory_usage || s.memory }));
                setEvents(res.data.events || []);
                setRequiredPorts(res.data.required_ports || []);
                setMockMode(res.data.mock_mode);
            } catch (e) {
                setEvents([
                    { time: new Date().toLocaleTimeString(), type: 'success', message: 'Origin-001 connected' },
                    { time: new Date().toLocaleTimeString(), type: 'error', message: 'Blocked SYN flood from 45.33.32.156' },
                    { time: new Date().toLocaleTimeString(), type: 'info', message: 'GeoIP database updated' },
                    { time: new Date().toLocaleTimeString(), type: 'warning', message: 'High traffic on port 20001' },
                ]);
                setRequiredPorts([
                    { port: 51820, protocol: 'UDP', service: 'WireGuard', description: 'VPN Tunnel' },
                    { port: 20001, protocol: 'UDP', service: 'Game', description: 'Reforger Game' },
                    { port: 17777, protocol: 'UDP', service: 'Browser', description: 'Server Browser' },
                ]);
            }
        };
        fetchStatus();
        const fetchFirewall = async () => {
            try { const res = await client.get('/firewall/status'); setFirewallRules(res.data.rules || ''); } catch (e) { setFirewallRules('Mock rules'); }
        };
        fetchFirewall();
    }, []);

    useEffect(() => {
        const interval = setInterval(() => {
            setData(prev => {
                const newPoint = { time: new Date().toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }), allowed: Math.floor(Math.random() * 500) + 200, blocked: Math.floor(Math.random() * 100) + 10 };
                return [...prev.slice(1), newPoint];
            });
            setStats(prev => ({ ...prev, connections: Math.max(100, prev.connections + Math.floor(Math.random() * 40) - 20), blocked: prev.blocked + Math.floor(Math.random() * 3) }));
            setIpTraffic(prev => prev.map(ip => ({ ...ip, pps: Math.max(50, ip.pps + Math.floor(Math.random() * 100) - 50), lastSeen: ip.status === 'blocked' ? '1s ago' : `${Math.floor(Math.random() * 10)}s ago` })));
        }, 2000);
        return () => clearInterval(interval);
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
                    <StatCard icon={<Shield sx={{ color: '#fff', fontSize: 20 }} />} title="Defense Status" value="ACTIVE" gradient="linear-gradient(135deg, #e65100, #ffab00)" />
                </Grid>
            </Grid>

            {/* Row 2: Live Traffic Monitor (Full Width) - Direct child of Box for maximum expansion */}
            <Card sx={{ bgcolor: '#111', borderRadius: 2, border: '1px solid #1a1a1a', height: 420, mb: 3, mx: 0 }}>
                <CardContent sx={{ p: 3, height: '100%', display: 'flex', flexDirection: 'column' }}>
                    <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between' }}>
                        <Typography variant="h6" sx={{ color: '#eee', fontWeight: 'bold' }}>📊 Live Traffic Monitor (PPS)</Typography>
                        <Chip label="Global Traffic" size="small" color="primary" variant="outlined" />
                    </Box>
                    <Box sx={{ flexGrow: 1 }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={data} margin={{ top: 10, right: 0, left: 0, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="allowedG" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#00e5ff" stopOpacity={0.4} /><stop offset="95%" stopColor="#00e5ff" stopOpacity={0} /></linearGradient>
                                    <linearGradient id="blockedG" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#f50057" stopOpacity={0.4} /><stop offset="95%" stopColor="#f50057" stopOpacity={0} /></linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                                <XAxis dataKey="time" stroke="#444" tick={{ fontSize: 10 }} interval="preserveStartEnd" minTickGap={30} />
                                <YAxis stroke="#444" tick={{ fontSize: 11 }} orientation="right" />
                                <Tooltip contentStyle={{ backgroundColor: '#000', border: '1px solid #444', fontSize: 12, borderRadius: 4 }} />
                                <Area type="monotone" dataKey="allowed" stroke="#00e5ff" strokeWidth={3} fill="url(#allowedG)" name="Allowed" animationDuration={500} />
                                <Area type="monotone" dataKey="blocked" stroke="#f50057" strokeWidth={3} fill="url(#blockedG)" name="Blocked" animationDuration={500} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </Box>
                </CardContent>
            </Card>

            {/* Row 3: Unified Data Views */}
            <Grid container spacing={3}>
                {/* Left Column: Per-IP Traffic (Expanded) */}
                <Grid item xs={12} lg={8}>
                    <Card sx={{ bgcolor: '#111', borderRadius: 2, border: '1px solid #1a1a1a', height: '100%', minHeight: 660 }}>
                        <CardContent sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
                            <Typography variant="subtitle1" sx={{ mb: 2, color: '#888' }}>🌐 Per-IP Traffic (Real-time)</Typography>
                            <TableContainer sx={{ flexGrow: 1 }}>
                                <Table stickyHeader size="small">
                                    <TableHead>
                                        <TableRow sx={{ '& th': { bgcolor: '#111', color: '#888', fontWeight: 'bold', borderColor: '#222' } }}>
                                            <TableCell>IP Address</TableCell>
                                            <TableCell>Country</TableCell>
                                            <TableCell align="right">PPS</TableCell>
                                            <TableCell>Status</TableCell>
                                            <TableCell>Last Seen</TableCell>
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {ipTraffic.map((row, i) => (
                                            <TableRow key={i} sx={{ '& td': { borderColor: '#222', py: 1.5 } }}>
                                                <TableCell sx={{ fontFamily: 'monospace', color: '#00e5ff', fontSize: 13 }}>{row.ip}</TableCell>
                                                <TableCell sx={{ fontSize: 12 }}>{row.country}</TableCell>
                                                <TableCell align="right" sx={{ color: row.pps > 500 ? '#f50057' : '#00c853', fontWeight: 'bold' }}>{row.pps}</TableCell>
                                                <TableCell>
                                                    <Chip label={row.status} size="small" sx={{ bgcolor: row.status === 'allowed' ? '#00c85320' : '#f5005720', color: row.status === 'allowed' ? '#00c853' : '#f50057', fontWeight: 'bold', height: 20 }} />
                                                </TableCell>
                                                <TableCell sx={{ color: '#666', fontSize: 12 }}>{row.lastSeen}</TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            </TableContainer>
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
                                {[{ name: 'CPU Usage', val: stats.cpu, color: 'primary' }, { name: 'Memory Usage', val: stats.memory, color: 'success' }, { name: 'Disk I/O', val: stats.disk, color: 'warning' }].map(s => (
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
                                    {events.map((e, i) => (
                                        <Box key={i} sx={{ display: 'flex', alignItems: 'center', py: 0.5, borderBottom: '1px solid #222' }}>
                                            {eventIcons[e.type]}
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
                                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{firewallRules || '# No rules active or mock mode.'}</pre>
                                </Paper>
                            </CardContent>
                        </Card>

                    </Box>
                </Grid>
            </Grid>
        </Box>
    );
}
