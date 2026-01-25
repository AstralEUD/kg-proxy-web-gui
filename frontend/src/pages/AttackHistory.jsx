import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    Box, Typography, Card, CardContent, Grid, Table, TableBody, TableCell, TableContainer,
    TableHead, TableRow, TablePagination, Chip, CircularProgress, FormControl, InputLabel, Select, MenuItem
} from '@mui/material';
import { Security, TrendingUp, Block, Public } from '@mui/icons-material';
import client from '../api/client';

export default function AttackHistory() {
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(25);
    const [filterType, setFilterType] = useState('');

    // Fetch attack history
    const { data: historyData, isLoading } = useQuery({
        queryKey: ['attack-history', page, rowsPerPage, filterType],
        queryFn: async () => {
            const params = new URLSearchParams({
                page: page + 1,
                limit: rowsPerPage,
            });
            if (filterType) params.append('type', filterType);
            const res = await client.get(`/attacks?${params.toString()}`);
            return res.data;
        },
    });

    // Fetch attack stats
    const { data: stats } = useQuery({
        queryKey: ['attack-stats'],
        queryFn: async () => {
            const res = await client.get('/attacks/stats');
            return res.data;
        },
    });

    const StatCard = ({ icon, title, value, color }) => (
        <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
            <CardContent sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: `${color}20` }}>
                    {icon}
                </Box>
                <Box>
                    <Typography variant="h4" sx={{ color: '#fff', fontWeight: 'bold' }}>
                        {typeof value === 'number' ? value.toLocaleString() : value || '0'}
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#888' }}>{title}</Typography>
                </Box>
            </CardContent>
        </Card>
    );

    const getAttackTypeColor = (type) => {
        switch (type) {
            case 'flood': return '#f50057';
            case 'geoip_violation': return '#ff9800';
            case 'rate_limit': return '#ffeb3b';
            case 'blacklist': return '#9c27b0';
            default: return '#00e5ff';
        }
    };

    const getActionColor = (action) => {
        switch (action) {
            case 'blocked': return 'error';
            case 'rate_limited': return 'warning';
            case 'warned': return 'info';
            default: return 'default';
        }
    };

    return (
        <Box sx={{ width: '100%' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <Security sx={{ color: '#f50057', mr: 1, fontSize: 32 }} />
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#fff' }}>Attack History</Typography>
            </Box>

            {/* Stats Cards */}
            <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                        icon={<Block sx={{ color: '#f50057', fontSize: 28 }} />}
                        title="Today's Attacks"
                        value={stats?.today_count}
                        color="#f50057"
                    />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                        icon={<TrendingUp sx={{ color: '#ff9800', fontSize: 28 }} />}
                        title="This Week"
                        value={stats?.week_count}
                        color="#ff9800"
                    />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                        icon={<Public sx={{ color: '#00e5ff', fontSize: 28 }} />}
                        title="Top Country"
                        value={stats?.top_country || 'N/A'}
                        color="#00e5ff"
                    />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                        icon={<Security sx={{ color: '#00c853', fontSize: 28 }} />}
                        title="Total Blocked"
                        value={stats?.total_blocked}
                        color="#00c853"
                    />
                </Grid>
            </Grid>

            {/* Filters */}
            <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
                <FormControl size="small" sx={{ minWidth: 180, bgcolor: '#111' }}>
                    <InputLabel sx={{ color: '#888' }}>Attack Type</InputLabel>
                    <Select
                        value={filterType}
                        label="Attack Type"
                        onChange={(e) => { setFilterType(e.target.value); setPage(0); }}
                        sx={{ color: '#fff', '& .MuiOutlinedInput-notchedOutline': { borderColor: '#333' } }}
                    >
                        <MenuItem value="">All Types</MenuItem>
                        <MenuItem value="flood">Flood Attack</MenuItem>
                        <MenuItem value="geoip_violation">GeoIP Violation</MenuItem>
                        <MenuItem value="rate_limit">Rate Limit</MenuItem>
                        <MenuItem value="blacklist">Blacklist</MenuItem>
                    </Select>
                </FormControl>
            </Box>

            {/* Attack History Table */}
            <Card sx={{ bgcolor: '#111', border: '1px solid #222' }}>
                {isLoading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                    </Box>
                ) : historyData?.events?.length === 0 ? (
                    <Box sx={{ p: 4, textAlign: 'center' }}>
                        <Security sx={{ fontSize: 48, color: '#333', mb: 2 }} />
                        <Typography variant="h6" color="textSecondary">No attack events recorded</Typography>
                        <Typography variant="body2" color="textSecondary">Attack events will appear here when detected</Typography>
                    </Box>
                ) : (
                    <>
                        <TableContainer>
                            <Table>
                                <TableHead>
                                    <TableRow sx={{ '& th': { bgcolor: '#0a0a0a', color: '#888', fontWeight: 'bold' } }}>
                                        <TableCell>Timestamp</TableCell>
                                        <TableCell>Source IP</TableCell>
                                        <TableCell>Country</TableCell>
                                        <TableCell>Attack Type</TableCell>
                                        <TableCell align="right">PPS</TableCell>
                                        <TableCell align="right">Packets</TableCell>
                                        <TableCell>Action</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {historyData?.events?.map((event) => (
                                        <TableRow key={event.id} hover sx={{ '&:hover': { bgcolor: '#ffffff05' } }}>
                                            <TableCell sx={{ color: '#666', fontFamily: 'monospace', fontSize: 11 }}>
                                                {new Date(event.timestamp).toLocaleString()}
                                            </TableCell>
                                            <TableCell sx={{ color: '#00e5ff', fontFamily: 'monospace' }}>
                                                {event.source_ip}
                                            </TableCell>
                                            <TableCell>
                                                <Chip
                                                    label={event.country_code || 'XX'}
                                                    size="small"
                                                    sx={{ bgcolor: '#333', color: '#fff', fontWeight: 'bold', minWidth: 36 }}
                                                />
                                            </TableCell>
                                            <TableCell>
                                                <Chip
                                                    label={event.attack_type}
                                                    size="small"
                                                    sx={{
                                                        bgcolor: `${getAttackTypeColor(event.attack_type)}20`,
                                                        color: getAttackTypeColor(event.attack_type),
                                                        borderRadius: 1
                                                    }}
                                                />
                                            </TableCell>
                                            <TableCell align="right" sx={{ color: event.pps > 10000 ? '#f50057' : '#fff', fontWeight: event.pps > 10000 ? 'bold' : 'normal' }}>
                                                {event.pps?.toLocaleString() || '-'}
                                            </TableCell>
                                            <TableCell align="right" sx={{ color: '#aaa', fontFamily: 'monospace' }}>
                                                {event.count > 0 ? event.count.toLocaleString() : '-'}
                                            </TableCell>
                                            <TableCell>
                                                <Chip
                                                    label={event.action?.toUpperCase()}
                                                    size="small"
                                                    color={getActionColor(event.action)}
                                                    sx={{ borderRadius: 1, fontSize: 10 }}
                                                />
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </TableContainer>
                        <TablePagination
                            rowsPerPageOptions={[10, 25, 50]}
                            component="div"
                            count={historyData?.total || 0}
                            rowsPerPage={rowsPerPage}
                            page={page}
                            onPageChange={(e, p) => setPage(p)}
                            onRowsPerPageChange={(e) => { setRowsPerPage(parseInt(e.target.value, 10)); setPage(0); }}
                            sx={{ color: '#888', borderTop: '1px solid #222' }}
                        />
                    </>
                )}
            </Card>
        </Box>
    );
}
