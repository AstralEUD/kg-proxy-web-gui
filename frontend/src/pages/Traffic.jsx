import React, { useState, useEffect } from 'react';
import {
    Box, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    TextField, InputAdornment, Chip, Grid, Card, CardContent, TablePagination, TableSortLabel,
    MenuItem, Select, FormControl, InputLabel, CircularProgress, Button, Dialog, DialogTitle,
    DialogContent, DialogActions, Paper, ToggleButton, ToggleButtonGroup
} from '@mui/material';
import { Search, Speed, FilterList, Router, Dns, Security, TrendingUp } from '@mui/icons-material';
import { ServicePipe, WorldMap2D } from '../components/Visualizations';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, AreaChart, Area } from 'recharts';
import client from '../api/client';

export default function Traffic() {
    const [data, setData] = useState([]);
    const [filteredData, setFilteredData] = useState([]);
    const [search, setSearch] = useState('');
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(15);
    const [order, setOrder] = useState('desc');
    const [orderBy, setOrderBy] = useState('pps');

    const [filterStatus, setFilterStatus] = useState('all');
    const [filterRisk, setFilterRisk] = useState('all');

    const [backendStats, setBackendStats] = useState({ connections: 0, uptime: '-', mock_mode: true, required_ports: [] });
    const [loading, setLoading] = useState(true);
    const [portsOpen, setPortsOpen] = useState(false);

    // Traffic History Chart
    const [historyData, setHistoryData] = useState([]);
    const [historyRange, setHistoryRange] = useState('1h');

    // Fetch traffic history
    useEffect(() => {
        const fetchHistory = async () => {
            try {
                const res = await client.get(`/traffic/history?range=${historyRange}`);
                if (res.data.history) {
                    setHistoryData(res.data.history.map(h => ({
                        ...h,
                        time: new Date(h.timestamp).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }),
                        allowed_pps: h.allowed_pps || 0,
                        blocked_pps: h.blocked_pps || 0,
                        total_pps: h.total_pps || 0,
                    })));
                }
            } catch (err) {
                console.error("Failed to fetch traffic history:", err);
            }
        };
        fetchHistory();
        const interval = setInterval(fetchHistory, 60000); // Update every minute
        return () => clearInterval(interval);
    }, [historyRange]);

    // Fetch real backend status and eBPF traffic data
    useEffect(() => {
        const fetchStats = async () => {
            try {
                const res = await client.get('/status');
                setBackendStats(res.data);
                setLoading(false);

                // Fetch eBPF traffic data
                try {
                    const trafficRes = await client.get('/traffic/data');
                    if (trafficRes.data.enabled && trafficRes.data.data) {
                        setData(trafficRes.data.data);
                    } else {
                        setData([]);
                    }
                } catch (trafficErr) {
                    console.error("Failed to fetch traffic data:", trafficErr);
                    setData([]);
                }
            } catch (err) {
                console.error("Failed to fetch status:", err);
                setLoading(false);
            }
        };

        fetchStats();
        const interval = setInterval(fetchStats, 5000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        let res = [...data];
        if (search) {
            const terms = search.toLowerCase().split(' ').filter(t => t.trim() !== '');
            res = res.filter(d => {
                const searchString = `${d.ip} ${d.countryName} ${d.countryCode} ${d.status}`.toLowerCase();
                return terms.every(term => searchString.includes(term));
            });
        }
        if (filterStatus !== 'all') res = res.filter(d => d.status === filterStatus);
        if (filterRisk !== 'all') {
            if (filterRisk === 'high') res = res.filter(d => d.risk_score > 70);
            if (filterRisk === 'medium') res = res.filter(d => d.risk_score > 30 && d.risk_score <= 70);
            if (filterRisk === 'low') res = res.filter(d => d.risk_score <= 30);
        }
        res.sort((a, b) => {
            if (orderBy === 'pps' || orderBy === 'risk_score') {
                return order === 'asc' ? a[orderBy] - b[orderBy] : b[orderBy] - a[orderBy];
            }
            return order === 'asc' ? a[orderBy].localeCompare(b[orderBy]) : b[orderBy].localeCompare(a[orderBy]);
        });
        setFilteredData(res);
    }, [data, search, order, orderBy, filterStatus, filterRisk]);

    const handleSort = (property) => {
        const isAsc = orderBy === property && order === 'asc';
        setOrder(isAsc ? 'desc' : 'asc');
        setOrderBy(property);
    };

    return (
        <Box sx={{ width: '100%' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3, gap: 2 }}>
                <Speed sx={{ color: '#00e5ff', fontSize: 32 }} />
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#fff' }}>Traffic Analysis</Typography>
                <Chip
                    label={backendStats.mock_mode ? 'MOCK' : 'LIVE'}
                    size="small"
                    sx={{
                        bgcolor: backendStats.mock_mode ? '#ffab0030' : '#00c85330',
                        color: backendStats.mock_mode ? '#ffab00' : '#00c853',
                        fontWeight: 'bold'
                    }}
                />
            </Box>

            {/* Service Pipe Visualization */}
            <Box sx={{ mb: 3 }}>
                <ServicePipe
                    activeCount={data.length}
                    totalCount={data.length}
                    passedCount={filteredData.filter(d => d.status === 'allowed').length}
                />
            </Box>

            {/* Traffic History Chart */}
            <Card sx={{ bgcolor: '#111', border: '1px solid #222', mb: 3 }}>
                <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                        <Typography variant="h6" sx={{ color: '#fff', display: 'flex', alignItems: 'center' }}>
                            <TrendingUp sx={{ mr: 1, color: '#00e5ff' }} /> Traffic History
                        </Typography>
                        <ToggleButtonGroup
                            size="small"
                            value={historyRange}
                            exclusive
                            onChange={(e, val) => val && setHistoryRange(val)}
                            sx={{ '& .MuiToggleButton-root': { color: '#888', borderColor: '#333' }, '& .Mui-selected': { bgcolor: '#00e5ff20', color: '#00e5ff' } }}
                        >
                            <ToggleButton value="1h">1H</ToggleButton>
                            <ToggleButton value="6h">6H</ToggleButton>
                            <ToggleButton value="24h">24H</ToggleButton>
                            <ToggleButton value="7d">7D</ToggleButton>
                        </ToggleButtonGroup>
                    </Box>

                    {historyData.length === 0 ? (
                        <Box sx={{ height: 250, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <Typography color="textSecondary">No historical data available yet. Data is collected every minute.</Typography>
                        </Box>
                    ) : (
                        <ResponsiveContainer width="100%" height={250}>
                            <AreaChart data={historyData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#00e5ff" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#00e5ff" stopOpacity={0} />
                                    </linearGradient>
                                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#f50057" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#f50057" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                <XAxis dataKey="time" stroke="#666" tick={{ fill: '#888', fontSize: 11 }} />
                                <YAxis stroke="#666" tick={{ fill: '#888', fontSize: 11 }} tickFormatter={(v) => v >= 1000 ? `${(v / 1000).toFixed(0)}K` : v} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333', borderRadius: 8 }}
                                    labelStyle={{ color: '#fff' }}
                                    formatter={(value, name) => [value.toLocaleString() + ' PPS', name === 'allowed_pps' ? 'Allowed' : 'Blocked']}
                                />
                                <Legend wrapperStyle={{ color: '#888' }} formatter={(value) => value === 'allowed_pps' ? 'Allowed' : 'Blocked'} />
                                <Area type="monotone" dataKey="allowed_pps" stroke="#00e5ff" fillOpacity={1} fill="url(#colorAllowed)" />
                                <Area type="monotone" dataKey="blocked_pps" stroke="#f50057" fillOpacity={1} fill="url(#colorBlocked)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    )}
                </CardContent>
            </Card>

            {/* Flex Container for Map & Filters */}
            <Box sx={{ display: 'flex', gap: 3, flexDirection: { xs: 'column', lg: 'row' }, mb: 3 }}>
                {/* 2D World Map (75% Width) */}
                <Box sx={{ flex: 3, minWidth: 0 }}>
                    <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: 420, overflow: 'hidden' }}>
                        <CardContent sx={{ p: 0, height: '100%', position: 'relative', bgcolor: '#050505', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                            <Typography variant="subtitle2" sx={{ position: 'absolute', top: 16, left: 16, zIndex: 10, color: '#888' }}>
                                🌍 Global Traffic Map
                            </Typography>
                            <Box sx={{ position: 'absolute', top: 16, right: 16, zIndex: 10, display: 'flex', gap: 1 }}>
                                <Button
                                    size="small"
                                    variant="outlined"
                                    startIcon={<Router />}
                                    onClick={() => setPortsOpen(true)}
                                    sx={{ color: '#00e5ff', borderColor: '#00e5ff80', bgcolor: '#00000080' }}
                                >
                                    Required Ports
                                </Button>
                                <Chip
                                    label={backendStats.mock_mode ? "Simulation Data" : "Real-time Data"}
                                    size="small"
                                    color={backendStats.mock_mode ? "warning" : "success"}
                                    variant="outlined"
                                    sx={{ bgcolor: '#00000080' }}
                                />
                            </Box>
                            <Box sx={{ width: '100%', height: '100%', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                                <WorldMap2D data={filteredData} />
                            </Box>
                        </CardContent>
                    </Card>
                </Box>

                {/* Filters Panel (25% Width) */}
                <Box sx={{ flex: 1, minWidth: 300 }}>
                    <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: 420 }}>
                        <CardContent>
                            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                                <FilterList sx={{ color: '#00e5ff', mr: 1 }} />
                                <Typography variant="h6">Filters & Search</Typography>
                            </Box>

                            <TextField
                                fullWidth
                                variant="outlined"
                                size="small"
                                placeholder="Search IP or Country..."
                                value={search}
                                onChange={(e) => setSearch(e.target.value)}
                                sx={{ mb: 3, bgcolor: '#0a0a0a', '& .MuiOutlinedInput-root': { '& fieldset': { borderColor: '#333' } } }}
                                InputProps={{ startAdornment: <InputAdornment position="start"><Search sx={{ color: '#666' }} /></InputAdornment> }}
                            />

                            <Grid container spacing={2}>
                                <Grid item xs={12}>
                                    <FormControl fullWidth size="small" sx={{ bgcolor: '#0a0a0a' }}>
                                        <InputLabel sx={{ color: '#888' }}>Status</InputLabel>
                                        <Select value={filterStatus} label="Status" onChange={(e) => setFilterStatus(e.target.value)} sx={{ color: '#fff', '.MuiOutlinedInput-notchedOutline': { borderColor: '#333' } }}>
                                            <MenuItem value="all">All</MenuItem>
                                            <MenuItem value="allowed">Allowed</MenuItem>
                                            <MenuItem value="blocked">Blocked</MenuItem>
                                        </Select>
                                    </FormControl>
                                </Grid>
                                <Grid item xs={12}>
                                    <FormControl fullWidth size="small" sx={{ bgcolor: '#0a0a0a' }}>
                                        <InputLabel sx={{ color: '#888' }}>Risk Score</InputLabel>
                                        <Select value={filterRisk} label="Risk Score" onChange={(e) => setFilterRisk(e.target.value)} sx={{ color: '#fff', '.MuiOutlinedInput-notchedOutline': { borderColor: '#333' } }}>
                                            <MenuItem value="all">All</MenuItem>
                                            <MenuItem value="high">High (&gt;70)</MenuItem>
                                            <MenuItem value="medium">Medium (30-70)</MenuItem>
                                            <MenuItem value="low">Low (&lt;30)</MenuItem>
                                        </Select>
                                    </FormControl>
                                </Grid>
                            </Grid>

                            <Box sx={{ mt: 4, pt: 2, borderTop: '1px solid #333' }}>
                                <Typography variant="body2" color="textSecondary" gutterBottom>System Status:</Typography>
                                <Typography variant="h5" sx={{ color: '#00e5ff', fontWeight: 'bold', mb: 0.5 }}>
                                    {backendStats.connections} <span style={{ fontSize: 12 }}>connections</span>
                                </Typography>
                                <Typography variant="caption" color="textSecondary" display="block" sx={{ mb: 2 }}>
                                    Uptime: {backendStats.uptime}
                                </Typography>

                                <Typography variant="body2" color="textSecondary" gutterBottom sx={{ mt: 2 }}>Active Defenses:</Typography>
                                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                                    {backendStats.active_defenses?.length > 0 ? (
                                        backendStats.active_defenses.map((def, idx) => (
                                            <Box key={idx} sx={{ display: 'flex', alignItems: 'center' }}>
                                                <Box sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: '#00c853', mr: 1, boxShadow: '0 0 5px #00c853' }} />
                                                <Typography variant="caption" sx={{ color: '#ccc' }}>{def}</Typography>
                                            </Box>
                                        ))
                                    ) : (
                                        <Typography variant="caption" color="textSecondary" sx={{ fontStyle: 'italic' }}>Running basic checks only</Typography>
                                    )}
                                </Box>
                            </Box>
                        </CardContent>
                    </Card>
                </Box>
            </Box>

            {/* Main Table */}
            <Card sx={{ bgcolor: '#111', border: '1px solid #222', mt: 3 }}>
                {loading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                    </Box>
                ) : filteredData.length === 0 ? (
                    <Box sx={{ p: 4, textAlign: 'center' }}>
                        <Speed sx={{ fontSize: 48, color: '#333', mb: 2 }} />
                        <Typography variant="h6" color="textSecondary">
                            {backendStats.mock_mode ? 'No Traffic Data (Mock Mode)' : 'No Traffic Data Yet'}
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                            {backendStats.mock_mode
                                ? 'Deploy to Linux server for real traffic monitoring.'
                                : 'Traffic data will appear here once eBPF XDP integration is configured.'}
                        </Typography>
                    </Box>
                ) : (
                    <>
                        <TableContainer>
                            <Table stickyHeader>
                                <TableHead>
                                    <TableRow sx={{ '& th': { bgcolor: '#0a0a0a', color: '#888', fontWeight: 'bold' } }}>
                                        <TableCell>
                                            <TableSortLabel active={orderBy === 'ip'} direction={orderBy === 'ip' ? order : 'asc'} onClick={() => handleSort('ip')}>IP Address</TableSortLabel>
                                        </TableCell>
                                        <TableCell align="right">Port</TableCell>
                                        <TableCell>Country</TableCell>
                                        <TableCell align="right">
                                            <TableSortLabel active={orderBy === 'pps'} direction={orderBy === 'pps' ? order : 'asc'} onClick={() => handleSort('pps')}>PPS</TableSortLabel>
                                        </TableCell>
                                        <TableCell align="right">Traffic Est.</TableCell>
                                        <TableCell align="right">
                                            <TableSortLabel active={orderBy === 'risk_score'} direction={orderBy === 'risk_score' ? order : 'asc'} onClick={() => handleSort('risk_score')}>Risk Score</TableSortLabel>
                                        </TableCell>
                                        <TableCell>Status</TableCell>
                                        <TableCell align="right">Last Seen</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {filteredData.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage).map((row) => (
                                        <TableRow key={row.id} hover sx={{ '&:hover': { bgcolor: '#ffffff05' } }}>
                                            <TableCell sx={{ color: '#00e5ff', fontFamily: 'monospace' }}>{row.ip}</TableCell>
                                            <TableCell align="right" sx={{ color: '#aaa', fontFamily: 'monospace' }}>
                                                {row.port && row.port > 0 ? row.port : '-'}
                                            </TableCell>
                                            <TableCell>
                                                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                                    <Box component="span" sx={{ bgcolor: '#333', color: '#fff', px: 1, py: 0.5, borderRadius: 1, fontSize: 12, fontWeight: 'bold', minWidth: 28, textAlign: 'center' }}>
                                                        {row.countryCode}
                                                    </Box>
                                                    <Typography variant="body2" sx={{ ml: 1, color: '#aaa', fontSize: 12 }}>{row.countryName}</Typography>
                                                </Box>
                                            </TableCell>
                                            <TableCell align="right" sx={{ color: row.pps > 1000 ? '#f50057' : '#fff', fontWeight: row.pps > 1000 ? 'bold' : 'normal' }}>
                                                {row.pps.toLocaleString()}
                                            </TableCell>
                                            <TableCell align="right" sx={{ color: '#888' }}>{row.total_bytes}</TableCell>
                                            <TableCell align="right">
                                                <span style={{ color: row.risk_score > 70 ? '#f50057' : row.risk_score > 30 ? '#ffab00' : '#00c853', fontWeight: 'bold' }}>{row.risk_score}</span>
                                            </TableCell>
                                            <TableCell>
                                                <Chip
                                                    label={row.status.toUpperCase()}
                                                    size="small"
                                                    sx={{ bgcolor: row.status === 'allowed' ? '#00c85320' : '#f5005720', color: row.status === 'allowed' ? '#00c853' : '#f50057', borderRadius: 1, height: 20, fontSize: 10 }}
                                                />
                                            </TableCell>
                                            <TableCell align="right" sx={{ color: '#666', fontFamily: 'monospace', fontSize: 11 }}>{row.last_seen}</TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </TableContainer>
                        <TablePagination
                            rowsPerPageOptions={[15, 30, 50]}
                            component="div"
                            count={filteredData.length}
                            rowsPerPage={rowsPerPage}
                            page={page}
                            onPageChange={(e, p) => setPage(p)}
                            onRowsPerPageChange={(e) => { setRowsPerPage(parseInt(e.target.value, 10)); setPage(0); }}
                            sx={{ color: '#888', borderTop: '1px solid #222' }}
                        />
                    </>
                )}
            </Card>

            <Dialog open={portsOpen} onClose={() => setPortsOpen(false)} PaperProps={{ sx: { bgcolor: '#111', border: '1px solid #333', minWidth: 500 } }}>
                <DialogTitle sx={{ color: '#fff', display: 'flex', alignItems: 'center' }}>
                    <Router sx={{ mr: 1, color: '#00e5ff' }} />
                    Firewall Configuration Guide
                </DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                        Please ensure the following ports are OPEN on your VPS firewall (e.g. AWS Security Group, Vultr Firewall).
                    </Typography>

                    <TableContainer component={Paper} sx={{ bgcolor: '#000', border: '1px solid #333' }}>
                        <Table size="small">
                            <TableHead>
                                <TableRow sx={{ '& th': { color: '#888', borderColor: '#222' } }}>
                                    <TableCell>Public Port</TableCell>
                                    <TableCell>Protocol</TableCell>
                                    <TableCell>Service Type</TableCell>
                                    <TableCell>Description</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {backendStats.required_ports && backendStats.required_ports.length > 0 ? (
                                    backendStats.required_ports.map((p, i) => (
                                        <TableRow key={i} sx={{ '& td': { color: '#ccc', borderColor: '#222' } }}>
                                            <TableCell sx={{ color: '#00e5ff', fontWeight: 'bold' }}>{p.port}</TableCell>
                                            <TableCell>{p.protocol}</TableCell>
                                            <TableCell>{p.service}</TableCell>
                                            <TableCell sx={{ color: '#888' }}>{p.description}</TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    <TableRow>
                                        <TableCell colSpan={4} align="center" sx={{ color: '#666' }}>Loading or no ports required...</TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setPortsOpen(false)} sx={{ color: '#888' }}>Close</Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
