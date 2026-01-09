import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    Box, Button, Grid, Card, CardContent, CardActions, Typography,
    Dialog, DialogTitle, DialogContent, DialogActions, TextField,
    Stepper, Step, StepLabel, Paper, IconButton, Tooltip, Chip
} from '@mui/material';
import { Add as AddIcon, CloudQueue, Download, ContentCopy, Delete, CheckCircle, Edit as EditIcon } from '@mui/icons-material';
import QRCode from 'react-qr-code';
import client from '../api/client';

const getNextOriginName = (origins) => {
    const nums = origins?.map(o => {
        const m = o.name.match(/Origin-(\d+)/);
        return m ? parseInt(m[1]) : 0;
    }) || [];
    const max = nums.length > 0 ? Math.max(...nums) : 0;
    return `Origin-${String(max + 1).padStart(3, '0')}`;
};

const generateWgConfig = (origin, peerInfo, serverInfo) => {
    // Priority: Backend provided endpoint > Server Public IP
    const endpoint = peerInfo?.endpoint || `${serverInfo?.public_ip || '<VPS_IP>'}:${serverInfo?.wireguard_port || 51820}`;
    const allowedIPs = peerInfo?.allowed_ips || '10.200.0.0/24, 10.99.0.0/24';

    return `[Interface]
Address = ${origin?.wg_ip || '10.200.0.2'}/32
PrivateKey = ${peerInfo?.private_key || '<PRIVATE_KEY_HIDDEN>'}
DNS = 8.8.8.8

[Peer]
PublicKey = ${peerInfo?.server_public_key || serverInfo?.wireguard_public_key || '<VPS_PUBLIC_KEY>'}
Endpoint = ${endpoint}
AllowedIPs = ${allowedIPs}
PersistentKeepalive = 25`;
};

export default function Origins() {
    const [open, setOpen] = useState(false);
    const [editMode, setEditMode] = useState(false);
    const [editId, setEditId] = useState(null);
    const [activeStep, setActiveStep] = useState(0);
    const [createdOrigin, setCreatedOrigin] = useState(null);
    const [copied, setCopied] = useState(false);

    // Form state for editing
    const [formData, setFormData] = useState({
        name: '',
        wg_ip: '',
        reforger_game_port: 20001,
        reforger_browser_port: 17777,
        reforger_a2s_port: 27016
    });

    const queryClient = useQueryClient();

    const { data: serverInfo } = useQuery({
        queryKey: ['serverInfo'],
        queryFn: async () => {
            const res = await client.get('/server/info');
            return res.data;
        }
    });

    const { data: origins, isLoading } = useQuery({
        queryKey: ['origins'],
        queryFn: async () => {
            try {
                const res = await client.get('/origins');
                return res.data || [];
            } catch { return []; }
        },
    });

    const createMutation = useMutation({
        mutationFn: (data) => client.post('/origins', data),
        onSuccess: (response) => {
            queryClient.invalidateQueries(['origins']);
            setCreatedOrigin({
                origin: response.data.origin || response.data,
                wg_config: response.data.wg_config || {},
            });
            setActiveStep(1);
        },
        onError: (error) => {
            alert(`Failed to create origin: ${error.response?.data?.error || error.message}`);
        },
    });

    const updateMutation = useMutation({
        mutationFn: ({ id, data }) => client.put(`/origins/${id}`, data),
        onSuccess: (response) => {
            queryClient.invalidateQueries(['origins']);
            setCreatedOrigin({
                origin: response.data.origin,
                wg_config: response.data.wg_config,
            });
            setActiveStep(1); // Go to config view to show updated AllowedIPs
        },
        onError: (error) => {
            alert(`Failed to update origin: ${error.response?.data?.error || error.message}`);
        },
    });

    const deleteMutation = useMutation({
        mutationFn: (id) => client.delete(`/origins/${id}`),
        onSuccess: () => queryClient.invalidateQueries(['origins']),
    });

    const handleOpenCreate = () => {
        setEditMode(false);
        setEditId(null);

        // Auto-generate defaults for Create mode
        const name = getNextOriginName(origins);
        const usedSuffixes = origins?.map(o => parseInt(o.wg_ip.split('.')[3])) || [];
        let nextSuffix = 2;
        while (usedSuffixes.includes(nextSuffix)) {
            nextSuffix++;
        }
        const wgIp = `10.200.0.${nextSuffix}`;

        setFormData({
            name: name,
            wg_ip: wgIp,
            reforger_game_port: 20001,
            reforger_browser_port: 17777,
            reforger_a2s_port: 27016
        });

        setActiveStep(0);
        setOpen(true);
    };

    const handleOpenEdit = (origin) => {
        setEditMode(true);
        setEditId(origin.id);
        setFormData({
            name: origin.name,
            wg_ip: origin.wg_ip,
            reforger_game_port: origin.reforger_game_port || 20001,
            reforger_browser_port: origin.reforger_browser_port || 17777,
            reforger_a2s_port: origin.reforger_a2s_port || 27016
        });
        setActiveStep(0);
        setOpen(true);
    };

    const handleSubmit = () => {
        if (editMode) {
            updateMutation.mutate({ id: editId, data: formData });
        } else {
            // Use user-defined values from form
            createMutation.mutate({ name: formData.name, wg_ip: formData.wg_ip });
        }
    };

    const handleDownload = (originData = null) => {
        const target = originData || createdOrigin;
        if (!target) return;
        const config = generateWgConfig(target.origin, target.wg_config || {}, serverInfo);
        const blob = new Blob([config], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${target.origin?.name || 'origin'}.conf`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const handleCopy = () => {
        if (!createdOrigin) return;
        const config = generateWgConfig(createdOrigin.origin, createdOrigin.wg_config, serverInfo);
        navigator.clipboard.writeText(config);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleClose = () => {
        setOpen(false);
        setActiveStep(0);
        setCreatedOrigin(null);
    };

    return (
        <Box sx={{ bgcolor: '#0a0a0a', minHeight: '100%', width: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <CloudQueue sx={{ color: '#00e5ff', mr: 1, fontSize: 28 }} />
                    <Typography variant="h5" sx={{ fontWeight: 'bold', color: '#00e5ff' }}>
                        Origin Servers
                    </Typography>
                </Box>
                <Button
                    variant="contained"
                    size="small"
                    startIcon={<AddIcon />}
                    onClick={handleOpenCreate}
                    sx={{
                        background: 'linear-gradient(45deg, #00e5ff, #00b8d4)',
                        color: '#000',
                        fontWeight: 'bold',
                    }}
                >
                    Create Origin
                </Button>
            </Box>

            {origins?.length === 0 && !isLoading ? (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                    <CloudQueue sx={{ fontSize: 48, color: '#333', mb: 2 }} />
                    <Typography variant="h6" color="textSecondary">No Origins Configured</Typography>
                    <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
                        Create your first Origin server to start routing traffic.
                    </Typography>
                    <Button variant="outlined" startIcon={<AddIcon />} onClick={handleOpenCreate}>
                        Create Origin
                    </Button>
                </Box>
            ) : (
                <Grid container spacing={2}>
                    {origins?.map((origin) => (
                        <Grid item xs={12} sm={6} lg={4} key={origin.id}>
                            <Card sx={{
                                bgcolor: '#111',
                                borderRadius: 2,
                                border: '1px solid #222',
                                '&:hover': { borderColor: '#00e5ff40' }
                            }}>
                                <CardContent sx={{ pb: 1 }}>
                                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                                        <CloudQueue sx={{ color: '#00e5ff', mr: 1, fontSize: 20 }} />
                                        <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>{origin.name}</Typography>
                                        <Chip
                                            label="Active"
                                            size="small"
                                            sx={{ ml: 'auto', bgcolor: '#00c85320', color: '#00c853', height: 20, fontSize: 10 }}
                                        />
                                    </Box>
                                    <Typography variant="caption" color="textSecondary" display="block">
                                        WireGuard IP: <code style={{ color: '#00e5ff' }}>{origin.wg_ip || 'N/A'}</code>
                                    </Typography>
                                    <Typography variant="caption" color="textSecondary">
                                        Manage ports in Services menu
                                    </Typography>
                                </CardContent>
                                <CardActions sx={{ borderTop: '1px solid #1a1a1a', px: 2, py: 1 }}>
                                    <Box sx={{ ml: 'auto', display: 'flex', gap: 1 }}>
                                        <Tooltip title="Edit">
                                            <IconButton
                                                size="small"
                                                sx={{ color: '#888', '&:hover': { color: '#00e5ff' } }}
                                                onClick={() => handleOpenEdit(origin)}
                                            >
                                                <EditIcon fontSize="small" />
                                            </IconButton>
                                        </Tooltip>
                                        <Tooltip title="Delete">
                                            <IconButton
                                                size="small"
                                                sx={{ color: '#888', '&:hover': { color: '#f50057' } }}
                                                onClick={() => deleteMutation.mutate(origin.id)}
                                            >
                                                <Delete fontSize="small" />
                                            </IconButton>
                                        </Tooltip>
                                    </Box>
                                </CardActions>
                            </Card>
                        </Grid>
                    ))}
                </Grid>
            )}

            {/* Dialog */}
            <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth PaperProps={{ sx: { bgcolor: '#111', borderRadius: 2 } }}>
                <DialogTitle sx={{ color: '#00e5ff', pb: 1 }}>
                    {editMode ? 'Edit Origin Server' : 'Create Origin Server'}
                </DialogTitle>
                <DialogContent>
                    <Stepper activeStep={activeStep} sx={{ mb: 3, pt: 1 }}>
                        <Step><StepLabel sx={{ '& .MuiStepLabel-label': { color: '#888' }, '& .Mui-active': { color: '#00e5ff' } }}>{editMode ? 'Edit' : 'Create'}</StepLabel></Step>
                        <Step><StepLabel sx={{ '& .MuiStepLabel-label': { color: '#888' }, '& .Mui-active': { color: '#00e5ff' } }}>Get Config</StepLabel></Step>
                    </Stepper>

                    {activeStep === 0 ? (
                        <Box sx={{ textAlign: 'center', py: 2 }}>
                            {!editMode && <CloudQueue sx={{ fontSize: 60, color: '#00e5ff', mb: 2 }} />}

                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
                                <TextField
                                    label="Name"
                                    size="small"
                                    value={formData.name}
                                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                    sx={{ bgcolor: '#1a1a1a', input: { color: '#fff' }, label: { color: '#888' } }}
                                />
                                <TextField
                                    label="WireGuard IP (Internal)"
                                    size="small"
                                    value={formData.wg_ip}
                                    onChange={(e) => setFormData({ ...formData, wg_ip: e.target.value })}
                                    sx={{ bgcolor: '#1a1a1a', input: { color: '#fff' }, label: { color: '#888' } }}
                                />
                                <Typography variant="caption" color="textSecondary" sx={{ textAlign: 'left' }}>
                                    Services and Ports are now configured in the 'Services' menu.
                                </Typography>
                            </Box>

                            <Box sx={{ mt: 3 }}>
                                <Button
                                    variant="contained"
                                    onClick={handleSubmit}
                                    disabled={createMutation.isPending || updateMutation.isPending || !serverInfo}
                                    sx={{ background: 'linear-gradient(45deg, #00e5ff, #00b8d4)', color: '#000', fontWeight: 'bold' }}
                                >
                                    {createMutation.isPending || updateMutation.isPending ? 'Processing...' : (editMode ? 'Save Changes' : 'Create Now')}
                                </Button>
                            </Box>
                        </Box>
                    ) : (
                        <Box>
                            <Box sx={{ textAlign: 'center', mb: 2 }}>
                                <CheckCircle sx={{ fontSize: 48, color: '#00c853', mb: 1 }} />
                                <Typography variant="subtitle1" color="success.main">
                                    {createdOrigin?.origin?.name} {editMode ? 'Updated!' : 'Created!'}
                                </Typography>
                            </Box>
                            <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2, p: 2, bgcolor: '#fff', borderRadius: 1 }}>
                                <QRCode value={generateWgConfig(createdOrigin?.origin, createdOrigin?.wg_config, serverInfo)} size={140} />
                            </Box>
                            <Paper sx={{ p: 1.5, bgcolor: '#0a0a0a', fontFamily: 'monospace', fontSize: 10, mb: 2, maxHeight: 120, overflow: 'auto' }}>
                                <pre style={{ margin: 0, color: '#0f0' }}>{generateWgConfig(createdOrigin?.origin, createdOrigin?.wg_config, serverInfo)}</pre>
                            </Paper>
                            <Box sx={{ display: 'flex', gap: 1 }}>
                                <Button fullWidth variant="outlined" size="small" startIcon={<ContentCopy />} onClick={handleCopy}>
                                    {copied ? 'Copied!' : 'Copy'}
                                </Button>
                                <Button fullWidth variant="contained" size="small" startIcon={<Download />} onClick={() => handleDownload()}>
                                    Download
                                </Button>
                            </Box>
                        </Box>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleClose} size="small" sx={{ color: '#888' }}>{activeStep === 1 ? 'Done' : 'Cancel'}</Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
