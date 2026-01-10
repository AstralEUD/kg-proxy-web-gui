import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    Box, Button, Grid, Card, CardContent, Typography, TextField,
    Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper,
    IconButton, Chip, Dialog, DialogTitle, DialogContent, DialogActions,
    Tab, Tabs, Alert
} from '@mui/material';
import { Add as AddIcon, Delete, CheckCircle, Block, Security, Search } from '@mui/icons-material';
import client from '../api/client';

// CIDR Helper: Calculate IP range from CIDR notation
function parseCIDRInfo(input) {
    if (!input) return null;
    const trimmed = input.trim();

    // Check if CIDR format
    const cidrMatch = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
    if (cidrMatch) {
        const prefix = parseInt(cidrMatch[5], 10);
        if (prefix < 0 || prefix > 32) return { valid: false, error: '잘못된 서브넷' };

        // Parse IP parts
        const ipParts = [parseInt(cidrMatch[1]), parseInt(cidrMatch[2]), parseInt(cidrMatch[3]), parseInt(cidrMatch[4])];
        if (ipParts.some(p => p > 255)) return { valid: false, error: '잘못된 IP' };

        // Calculate network address and broadcast address
        const ipNum = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
        const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
        const networkNum = (ipNum & mask) >>> 0;
        const broadcastNum = (networkNum | (~mask >>> 0)) >>> 0;

        const formatIP = (num) => [
            (num >>> 24) & 0xFF,
            (num >>> 16) & 0xFF,
            (num >>> 8) & 0xFF,
            num & 0xFF
        ].join('.');

        const startIP = formatIP(networkNum);
        const endIP = formatIP(broadcastNum);
        const hostCount = Math.pow(2, 32 - prefix);

        return {
            valid: true,
            type: 'cidr',
            prefix,
            hosts: hostCount,
            display: `${startIP} ~ ${endIP} (${hostCount.toLocaleString()}개)`
        };
    }

    // Check if single IP format
    const ipMatch = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipMatch) {
        const parts = [parseInt(ipMatch[1]), parseInt(ipMatch[2]), parseInt(ipMatch[3]), parseInt(ipMatch[4])];
        if (parts.some(p => p > 255)) return { valid: false, error: '잘못된 IP' };
        return { valid: true, type: 'single', display: '단일 IP' };
    }

    return { valid: false, error: '잘못된 형식' };
}

export default function SecurityRules() {
    const [tab, setTab] = useState(0);
    const [openAdd, setOpenAdd] = useState(false);
    const [addType, setAddType] = useState('allow'); // 'allow' or 'block'
    const [newItem, setNewItem] = useState({ ip: '', comment: '' });

    // CIDR Auto-calculation
    const cidrInfo = useMemo(() => parseCIDRInfo(newItem.ip), [newItem.ip]);

    // Check IP Tool State
    const [checkIP, setCheckIP] = useState('');
    const [checkResult, setCheckResult] = useState(null);

    const queryClient = useQueryClient();

    const { data: rules, isLoading } = useQuery({
        queryKey: ['securityRules'],
        queryFn: async () => {
            // We need to implement GET /security/rules endpoint or fetch individually
            // My previous backend implementation added GET /security/rules
            const res = await client.get('/security/rules');
            return res.data;
        }
    });

    const addMutation = useMutation({
        mutationFn: (data) => {
            const endpoint = data.type === 'allow' ? '/security/rules/allow' : '/security/rules/block';
            const payload = data.type === 'allow'
                ? { ip: data.ip, label: data.comment }
                : { ip: data.ip, reason: data.comment };
            return client.post(endpoint, payload);
        },
        onSuccess: () => {
            queryClient.invalidateQueries(['securityRules']);
            setOpenAdd(false);
            setNewItem({ ip: '', comment: '' });
        },
        onError: (err) => alert(err.response?.data?.error || err.message)
    });

    const deleteMutation = useMutation({
        mutationFn: ({ id, type }) => {
            const endpoint = type === 'allow' ? `/security/rules/allow/${id}` : `/security/rules/block/${id}`;
            return client.delete(endpoint);
        },
        onSuccess: () => queryClient.invalidateQueries(['securityRules'])
    });

    const checkMutation = useMutation({
        mutationFn: (ip) => client.get(`/security/check/${ip}`),
        onSuccess: (res) => setCheckResult(res.data),
        onError: (err) => setCheckResult({ error: err.message })
    });

    const handleAdd = () => {
        addMutation.mutate({ ...newItem, type: addType });
    };

    const handleDelete = (id, type) => {
        if (window.confirm('Are you sure you want to delete this rule?')) {
            deleteMutation.mutate({ id, type });
        }
    };

    return (
        <Box sx={{ bgcolor: '#0a0a0a', minHeight: '100%', width: '100%', p: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <Security sx={{ color: '#00e5ff', mr: 1, fontSize: 28 }} />
                <Typography variant="h5" sx={{ fontWeight: 'bold', color: '#fff' }}>
                    Access Control Rules
                </Typography>
            </Box>

            {/* Check IP Tool */}
            <Paper sx={{ p: 2, mb: 4, bgcolor: '#111', border: '1px solid #333' }}>
                <Typography variant="h6" sx={{ color: '#00e5ff', mb: 2, display: 'flex', alignItems: 'center' }}>
                    <Search sx={{ mr: 1 }} /> IP Status Check
                </Typography>
                <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                    <TextField
                        label="Enter IP Address"
                        size="small"
                        value={checkIP}
                        onChange={(e) => setCheckIP(e.target.value)}
                        sx={{ bgcolor: '#1a1a1a', input: { color: '#fff' }, label: { color: '#888' }, minWidth: 250 }}
                    />
                    <Button
                        variant="contained"
                        onClick={() => checkMutation.mutate(checkIP)}
                        disabled={!checkIP || checkMutation.isPending}
                        sx={{ bgcolor: '#333', '&:hover': { bgcolor: '#444' } }}
                    >
                        Check
                    </Button>
                    {checkResult && (
                        <Box sx={{ ml: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                            {checkResult.error ? (
                                <Chip label="Error" color="error" />
                            ) : (
                                <>
                                    <Chip
                                        label={checkResult.status?.toUpperCase()}
                                        color={checkResult.status === 'allowed' ? 'success' : 'error'}
                                        variant="outlined"
                                    />
                                    <Typography variant="body2" color="textSecondary">
                                        {checkResult.reason}
                                    </Typography>
                                </>
                            )}
                        </Box>
                    )}
                </Box>
            </Paper>

            <Box sx={{ borderBottom: 1, borderColor: '#333', mb: 2 }}>
                <Tabs value={tab} onChange={(e, v) => setTab(v)} textColor="inherit" IndicatorProps={{ sx: { bgcolor: '#00e5ff' } }}>
                    <Tab label="Whitelist (Allowed)" sx={{ color: tab === 0 ? '#00e5ff' : '#888' }} />
                    <Tab label="Blacklist (Blocked)" sx={{ color: tab === 1 ? '#f50057' : '#888' }} />
                </Tabs>
            </Box>

            <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}>
                <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => { setAddType(tab === 0 ? 'allow' : 'block'); setOpenAdd(true); }}
                    sx={{ bgcolor: tab === 0 ? '#00c853' : '#f50057', '&:hover': { filter: 'brightness(1.2)' } }}
                >
                    Add {tab === 0 ? 'Allow' : 'Block'} Rule
                </Button>
            </Box>

            <TableContainer component={Paper} sx={{ bgcolor: '#111', border: '1px solid #222' }}>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell sx={{ color: '#888' }}>IP Address</TableCell>
                            <TableCell sx={{ color: '#888' }}>{tab === 0 ? 'Label' : 'Reason'}</TableCell>
                            <TableCell sx={{ color: '#888' }}>Created At</TableCell>
                            <TableCell align="right" sx={{ color: '#888' }}>Action</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {(tab === 0 ? rules?.allowed : rules?.blocked)?.map((row) => (
                            <TableRow key={row.id}>
                                <TableCell sx={{ color: '#fff' }}>{row.ip}</TableCell>
                                <TableCell sx={{ color: '#ccc' }}>{row.label || row.reason || '-'}</TableCell>
                                <TableCell sx={{ color: '#666' }}>{new Date(row.created_at).toLocaleString()}</TableCell>
                                <TableCell align="right">
                                    <IconButton size="small" onClick={() => handleDelete(row.id, tab === 0 ? 'allow' : 'block')} sx={{ color: '#666', '&:hover': { color: '#f50057' } }}>
                                        <Delete />
                                    </IconButton>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* Add Dialog */}
            <Dialog open={openAdd} onClose={() => setOpenAdd(false)} PaperProps={{ sx: { bgcolor: '#1a1a1a', color: '#fff', minWidth: 400 } }}>
                <DialogTitle sx={{ color: addType === 'allow' ? '#00c853' : '#f50057' }}>
                    Add {addType === 'allow' ? 'Whitelist' : 'Blacklist'} Rule
                </DialogTitle>
                <DialogContent>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
                        <TextField
                            label="IP 주소 또는 CIDR"
                            placeholder="예: 192.168.1.0/24"
                            fullWidth
                            value={newItem.ip}
                            onChange={(e) => setNewItem({ ...newItem, ip: e.target.value })}
                            error={cidrInfo && !cidrInfo.valid}
                            helperText={cidrInfo ? (cidrInfo.valid ? cidrInfo.display : cidrInfo.error) : 'IP 주소 또는 CIDR (예: 10.0.0.0/8)'}
                            sx={{ '& input': { color: '#fff' }, '& label': { color: '#888' }, '& fieldset': { borderColor: '#444' }, '& .MuiFormHelperText-root': { color: cidrInfo?.valid ? '#00e5ff' : '#f50057' } }}
                        />
                        <TextField
                            label={addType === 'allow' ? "Label (Optional)" : "Reason (Optional)"}
                            fullWidth
                            value={newItem.comment}
                            onChange={(e) => setNewItem({ ...newItem, comment: e.target.value })}
                            sx={{ '& input': { color: '#fff' }, '& label': { color: '#888' }, '& fieldset': { borderColor: '#444' } }}
                        />
                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setOpenAdd(false)} sx={{ color: '#888' }}>Cancel</Button>
                    <Button variant="contained" onClick={handleAdd} sx={{ bgcolor: addType === 'allow' ? '#00c853' : '#f50057' }}>
                        Add Rule
                    </Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
