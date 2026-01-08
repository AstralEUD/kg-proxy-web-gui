import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    Box, Button, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    Paper, Chip, IconButton, Tooltip, Dialog, DialogTitle, DialogContent, DialogActions,
    TextField, FormControl, InputLabel, Select, MenuItem, Grid, CircularProgress
} from '@mui/material';
import { Add as AddIcon, Edit, Delete, Gamepad } from '@mui/icons-material';
import client from '../api/client';

export default function Services() {
    const [open, setOpen] = useState(false);
    const [editMode, setEditMode] = useState(false);
    const [editId, setEditId] = useState(null);

    const [formData, setFormData] = useState({
        name: '',
        origin_id: '',
        ports: [{ name: 'Game Port', protocol: 'UDP', public_port_display: '2302', private_port_display: '2302' }]
    });
    const queryClient = useQueryClient();

    // Fetch services from API
    const { data: services, isLoading } = useQuery({
        queryKey: ['services'],
        queryFn: async () => {
            const res = await client.get('/services');
            return res.data || [];
        },
    });

    // Fetch origins for dropdown
    const { data: origins } = useQuery({
        queryKey: ['origins'],
        queryFn: async () => {
            const res = await client.get('/origins');
            return res.data || [];
        },
    });

    // Create mutation
    const createMutation = useMutation({
        mutationFn: (data) => client.post('/services', data),
        onSuccess: () => {
            queryClient.invalidateQueries(['services']);
            handleClose();
        },
    });

    // Update mutation
    const updateMutation = useMutation({
        mutationFn: ({ id, data }) => client.put(`/services/${id}`, data),
        onSuccess: () => {
            queryClient.invalidateQueries(['services']);
            handleClose();
        },
    });

    // Delete mutation
    const deleteMutation = useMutation({
        mutationFn: (id) => client.delete(`/services/${id}`),
        onSuccess: () => queryClient.invalidateQueries(['services']),
    });

    const handleClose = () => {
        setOpen(false);
        setEditMode(false);
        setEditId(null);
        setFormData({
            name: '',
            origin_id: '',
            ports: [{ name: 'Game Port', protocol: 'UDP', public_port_display: '2302', private_port_display: '2302' }]
        });
    };

    const handleEdit = (service) => {
        setEditMode(true);
        setEditId(service.id);

        // Transform ports for display (combine start/end)
        const portsForDisplay = service.ports.map(p => ({
            name: p.name,
            protocol: p.protocol,
            public_port_display: p.public_port_end > 0 && p.public_port_end > p.public_port
                ? `${p.public_port}-${p.public_port_end}`
                : `${p.public_port}`,
            private_port_display: p.private_port_end > 0 && p.private_port_end > p.private_port
                ? `${p.private_port}-${p.private_port_end}`
                : `${p.private_port}`
        }));

        setFormData({
            name: service.name,
            origin_id: service.origin_id,
            ports: portsForDisplay
        });
        setOpen(true);
    };

    const parsePortString = (str) => {
        if (!str) return { start: 0, end: 0 };
        const parts = str.toString().split('-');
        const start = parseInt(parts[0]);
        if (isNaN(start)) return { start: 0, end: 0 };

        if (parts.length > 1) {
            const end = parseInt(parts[1]);
            return { start, end: isNaN(end) ? 0 : end };
        }
        return { start, end: 0 };
    };

    const handleSubmit = () => {
        const payload = {
            name: formData.name,
            origin_id: parseInt(formData.origin_id),
            ports: formData.ports.map(p => {
                const pub = parsePortString(p.public_port_display);
                const priv = parsePortString(p.private_port_display);

                // Smart range filling: if private is single but public is range, allow it (implicit mapping)
                // But usually we want explicit mapping. 
                // If user types "27015-27030" for public and "27015" for private, 
                // backend logic handles end calculation if PrivateEnd is 0? No, backend logic handles missing PrivateEnd.

                return {
                    name: p.name,
                    protocol: p.protocol,
                    public_port: pub.start,
                    public_port_end: pub.end,
                    private_port: priv.start,
                    private_port_end: priv.end
                };
            })
        };

        if (editMode) {
            updateMutation.mutate({ id: editId, data: payload });
        } else {
            createMutation.mutate(payload);
        }
    };

    const handleAddPort = () => {
        setFormData({
            ...formData,
            ports: [...formData.ports, { name: 'New Port', protocol: 'UDP', public_port_display: '', private_port_display: '' }]
        });
    };

    const handleRemovePort = (index) => {
        const newPorts = [...formData.ports];
        newPorts.splice(index, 1);
        setFormData({ ...formData, ports: newPorts });
    };

    const handlePortChange = (index, field, value) => {
        const newPorts = [...formData.ports];
        newPorts[index][field] = value;
        setFormData({ ...formData, ports: newPorts });
    };

    const getOriginName = (originId) => {
        const origin = origins?.find(o => o.id === originId);
        return origin?.name || `Origin-${originId}`;
    };

    const formatPort = (start, end) => {
        return (end > 0 && end > start) ? `${start}-${end}` : `${start}`;
    };

    return (
        <Box sx={{ width: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Gamepad sx={{ color: '#00e5ff', mr: 1, fontSize: 28 }} />
                    <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#00e5ff' }}>
                        Game Services
                    </Typography>
                </Box>
                <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => setOpen(true)}
                    sx={{
                        background: 'linear-gradient(45deg, #00e5ff, #00b8d4)',
                        color: '#000',
                        fontWeight: 'bold',
                    }}
                >
                    Add Service
                </Button>
            </Box>

            {isLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                    <CircularProgress />
                </Box>
            ) : services?.length === 0 ? (
                <Paper sx={{ p: 4, textAlign: 'center', bgcolor: '#111', border: '1px solid #222' }}>
                    <Gamepad sx={{ fontSize: 48, color: '#333', mb: 2 }} />
                    <Typography variant="h6" color="textSecondary">No Services Configured</Typography>
                    <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
                        Add your first game service to start routing traffic.
                    </Typography>
                    <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setOpen(true)}>
                        Add Service
                    </Button>
                </Paper>
            ) : (
                <TableContainer component={Paper} sx={{ bgcolor: '#111', borderRadius: 2, border: '1px solid #222' }}>
                    <Table>
                        <TableHead>
                            <TableRow sx={{ '& th': { borderBottom: '1px solid #333', color: '#888', fontWeight: 'bold' } }}>
                                <TableCell>Service Name</TableCell>
                                <TableCell>Target Origin</TableCell>
                                <TableCell>Port Forwarding Rules (Public -> Private)</TableCell>
                                <TableCell>Created</TableCell>
                                <TableCell align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {services?.map((service) => (
                                <TableRow
                                    key={service.id}
                                    sx={{
                                        '& td': { borderBottom: '1px solid #222' },
                                        '&:hover': { bgcolor: '#ffffff08' }
                                    }}
                                >
                                    <TableCell>
                                        <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                                            {service.name}
                                        </Typography>
                                    </TableCell>
                                    <TableCell sx={{ color: '#aaa' }}>{getOriginName(service.origin_id)}</TableCell>
                                    <TableCell>
                                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                                            {service.ports?.map((p, i) => (
                                                <Box key={i} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                    <Chip
                                                        label={p.protocol}
                                                        size="small"
                                                        sx={{
                                                            height: 16,
                                                            fontSize: 9,
                                                            bgcolor: p.protocol === 'UDP' ? '#ff980020' : '#2196f320',
                                                            color: p.protocol === 'UDP' ? '#ff9800' : '#2196f3'
                                                        }}
                                                    />
                                                    <code style={{ color: '#00e5ff', fontSize: 12 }}>
                                                        {formatPort(p.public_port, p.public_port_end)}
                                                    </code>
                                                    <span style={{ color: '#666', fontSize: 10 }}>➞</span>
                                                    <code style={{ color: '#aaa', fontSize: 12 }}>
                                                        {formatPort(p.private_port, p.private_port_end)}
                                                    </code>
                                                    {p.name && <span style={{ color: '#666', fontSize: 10 }}>({p.name})</span>}
                                                </Box>
                                            ))}
                                        </Box>
                                    </TableCell>
                                    <TableCell sx={{ color: '#666', fontSize: 12 }}>
                                        {new Date(service.created_at).toLocaleDateString()}
                                    </TableCell>
                                    <TableCell align="right">
                                        <Tooltip title="Edit">
                                            <IconButton
                                                size="small"
                                                sx={{ color: '#00e5ff', mr: 1 }}
                                                onClick={() => handleEdit(service)}
                                            >
                                                <Edit />
                                            </IconButton>
                                        </Tooltip>
                                        <Tooltip title="Delete">
                                            <IconButton
                                                size="small"
                                                sx={{ color: '#f50057' }}
                                                onClick={() => deleteMutation.mutate(service.id)}
                                            >
                                                <Delete />
                                            </IconButton>
                                        </Tooltip>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            )}

            {/* Add/Edit Service Dialog */}
            <Dialog open={open} onClose={handleClose} maxWidth="md" fullWidth PaperProps={{ sx: { bgcolor: '#111', borderRadius: 2 } }}>
                <DialogTitle sx={{ color: '#00e5ff' }}>
                    {editMode ? 'Edit Service' : 'Add New Service'}
                </DialogTitle>
                <DialogContent>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
                        <TextField
                            fullWidth
                            label="Service Name"
                            value={formData.name}
                            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                            placeholder="e.g., Arma Reforger #1"
                            sx={{ bgcolor: '#0a0a0a' }}
                        />
                        <FormControl fullWidth sx={{ bgcolor: '#0a0a0a' }}>
                            <InputLabel>Target Origin</InputLabel>
                            <Select
                                value={formData.origin_id}
                                label="Target Origin"
                                onChange={(e) => setFormData({ ...formData, origin_id: e.target.value })}
                            >
                                {origins?.map((origin) => (
                                    <MenuItem key={origin.id} value={origin.id}>{origin.name} ({origin.wg_ip})</MenuItem>
                                ))}
                            </Select>
                        </FormControl>

                        <Typography variant="subtitle2" sx={{ color: '#888', mt: 2 }}>Port Forwarding Rules (Supports Ranges e.g. 27015-27030)</Typography>
                        <Box sx={{ maxHeight: 300, overflowY: 'auto', pr: 1 }}>
                            {formData.ports.map((port, index) => (
                                <Grid container spacing={1} key={index} sx={{ mb: 1, alignItems: 'center' }}>
                                    <Grid item xs={2}>
                                        <FormControl fullWidth size="small" sx={{ bgcolor: '#0a0a0a' }}>
                                            <Select
                                                value={port.protocol}
                                                onChange={(e) => handlePortChange(index, 'protocol', e.target.value)}
                                            >
                                                <MenuItem value="UDP">UDP</MenuItem>
                                                <MenuItem value="TCP">TCP</MenuItem>
                                            </Select>
                                        </FormControl>
                                    </Grid>
                                    <Grid item xs={3}>
                                        <TextField
                                            label="Public (VPS)"
                                            size="small"
                                            fullWidth
                                            value={port.public_port_display}
                                            onChange={(e) => handlePortChange(index, 'public_port_display', e.target.value)}
                                            placeholder="2302 or 2300-2400"
                                            sx={{ bgcolor: '#0a0a0a' }}
                                        />
                                    </Grid>
                                    <Grid item xs={1} sx={{ textAlign: 'center', color: '#666' }}>➞</Grid>
                                    <Grid item xs={3}>
                                        <TextField
                                            label="Private (Origin)"
                                            size="small"
                                            fullWidth
                                            value={port.private_port_display}
                                            onChange={(e) => handlePortChange(index, 'private_port_display', e.target.value)}
                                            placeholder="2302 or 2300-2400"
                                            sx={{ bgcolor: '#0a0a0a' }}
                                        />
                                    </Grid>
                                    <Grid item xs={2}>
                                        <TextField
                                            label="Label"
                                            size="small"
                                            fullWidth
                                            value={port.name}
                                            onChange={(e) => handlePortChange(index, 'name', e.target.value)}
                                            sx={{ bgcolor: '#0a0a0a' }}
                                        />
                                    </Grid>
                                    <Grid item xs={1}>
                                        <IconButton size="small" onClick={() => handleRemovePort(index)} color="error">
                                            <Delete fontSize="small" />
                                        </IconButton>
                                    </Grid>
                                </Grid>
                            ))}
                        </Box>
                        <Button
                            startIcon={<AddIcon />}
                            size="small"
                            onClick={handleAddPort}
                            sx={{ alignSelf: 'flex-start' }}
                        >
                            Add Port Rule
                        </Button>

                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleClose}>Cancel</Button>
                    <Button
                        variant="contained"
                        onClick={handleSubmit}
                        disabled={!formData.name || !formData.origin_id || createMutation.isPending || updateMutation.isPending}
                        sx={{ background: 'linear-gradient(45deg, #00e5ff, #00b8d4)', color: '#000' }}
                    >
                        {createMutation.isPending || updateMutation.isPending ? 'Saving...' : (editMode ? 'Update Service' : 'Create Service')}
                    </Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
