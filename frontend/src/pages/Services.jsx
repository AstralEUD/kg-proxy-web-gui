import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    Box, Button, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    Paper, Chip, IconButton, Tooltip, Dialog, DialogTitle, DialogContent, DialogActions,
    TextField, FormControl, InputLabel, Select, MenuItem, Grid, CircularProgress
} from '@mui/material';
import { Add as AddIcon, Edit, Delete, PlayArrow, Stop, Gamepad } from '@mui/icons-material';
import client from '../api/client';

export default function Services() {
    const [open, setOpen] = useState(false);
    const [formData, setFormData] = useState({
        name: '',
        origin_id: '',
        public_game_port: 2302,
        public_browser_port: 2303,
        public_a2s_port: 2304
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
            setOpen(false);
            setFormData({ name: '', origin_id: '', public_game_port: 2302, public_browser_port: 2303, public_a2s_port: 2304 });
        },
    });

    // Delete mutation
    const deleteMutation = useMutation({
        mutationFn: (id) => client.delete(`/services/${id}`),
        onSuccess: () => queryClient.invalidateQueries(['services']),
    });

    const handleSubmit = () => {
        createMutation.mutate({
            name: formData.name,
            origin_id: parseInt(formData.origin_id),
            public_game_port: parseInt(formData.public_game_port),
            public_browser_port: parseInt(formData.public_browser_port),
            public_a2s_port: parseInt(formData.public_a2s_port)
        });
    };

    const getOriginName = (originId) => {
        const origin = origins?.find(o => o.id === originId);
        return origin?.name || `Origin-${originId}`;
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
                                <TableCell>Ports (Game / Browser / Query)</TableCell>
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
                                        <code style={{ color: '#00e5ff', fontSize: 12 }}>
                                            {service.public_game_port} / {service.public_browser_port} / {service.public_a2s_port}
                                        </code>
                                    </TableCell>
                                    <TableCell sx={{ color: '#666', fontSize: 12 }}>
                                        {new Date(service.created_at).toLocaleDateString()}
                                    </TableCell>
                                    <TableCell align="right">
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

            {/* Add Service Dialog */}
            <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth PaperProps={{ sx: { bgcolor: '#111', borderRadius: 2 } }}>
                <DialogTitle sx={{ color: '#00e5ff' }}>Add New Service</DialogTitle>
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
                        <Grid container spacing={2}>
                            <Grid item xs={4}>
                                <TextField
                                    fullWidth
                                    label="Game Port"
                                    type="number"
                                    value={formData.public_game_port}
                                    onChange={(e) => setFormData({ ...formData, public_game_port: e.target.value })}
                                    sx={{ bgcolor: '#0a0a0a' }}
                                />
                            </Grid>
                            <Grid item xs={4}>
                                <TextField
                                    fullWidth
                                    label="Browser Port"
                                    type="number"
                                    value={formData.public_browser_port}
                                    onChange={(e) => setFormData({ ...formData, public_browser_port: e.target.value })}
                                    sx={{ bgcolor: '#0a0a0a' }}
                                />
                            </Grid>
                            <Grid item xs={4}>
                                <TextField
                                    fullWidth
                                    label="Query Port"
                                    type="number"
                                    value={formData.public_a2s_port}
                                    onChange={(e) => setFormData({ ...formData, public_a2s_port: e.target.value })}
                                    sx={{ bgcolor: '#0a0a0a' }}
                                />
                            </Grid>
                        </Grid>
                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setOpen(false)}>Cancel</Button>
                    <Button
                        variant="contained"
                        onClick={handleSubmit}
                        disabled={!formData.name || !formData.origin_id || createMutation.isPending}
                        sx={{ background: 'linear-gradient(45deg, #00e5ff, #00b8d4)', color: '#000' }}
                    >
                        {createMutation.isPending ? 'Creating...' : 'Create Service'}
                    </Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
