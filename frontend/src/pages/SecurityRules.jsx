import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    Box, Button, Grid, Card, CardContent, Typography, TextField,
    Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper,
    IconButton, Chip, Dialog, DialogTitle, DialogContent, DialogActions,
    Tab, Tabs, Alert
} from '@mui/material';
import { Add as AddIcon, Delete, CheckCircle, Block, Security, Search } from '@mui/icons-material';
import client from '../api/client';

export default function SecurityRules() {
    const [tab, setTab] = useState(0);
    const [openAdd, setOpenAdd] = useState(false);
    const [addType, setAddType] = useState('allow'); // 'allow' or 'block'
    const [newItem, setNewItem] = useState({ ip: '', comment: '' });

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
                            label="IP Address"
                            fullWidth
                            value={newItem.ip}
                            onChange={(e) => setNewItem({ ...newItem, ip: e.target.value })}
                            sx={{ '& input': { color: '#fff' }, '& label': { color: '#888' }, '& fieldset': { borderColor: '#444' } }}
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
