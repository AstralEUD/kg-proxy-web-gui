import { useState } from 'react';
import {
    Box,
    Typography,
    Button,
    Card,
    CardContent,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Paper,
    IconButton,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    TextField,
    Tooltip,
    Chip
} from '@mui/material';
import {
    Add as AddIcon,
    Edit as EditIcon,
    Delete as DeleteIcon,
    Public as PublicIcon
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import client from '../api/client';

const CountryGroups = () => {
    const queryClient = useQueryClient();
    const [open, setOpen] = useState(false);
    const [editingGroup, setEditingGroup] = useState(null);
    const [formData, setFormData] = useState({ name: '', description: '', countries: '', color: '#ff0000' });

    const { data: groups, isLoading } = useQuery({
        queryKey: ['countryGroups'],
        queryFn: async () => {
            const res = await client.get('/security/countries/groups');
            return res.data;
        }
    });

    const createMutation = useMutation({
        mutationFn: (data) => client.post('/security/countries/groups', data),
        onSuccess: () => {
            queryClient.invalidateQueries(['countryGroups']);
            handleClose();
        }
    });

    const updateMutation = useMutation({
        mutationFn: ({ id, data }) => client.put(`/security/countries/groups/${id}`, data),
        onSuccess: () => {
            queryClient.invalidateQueries(['countryGroups']);
            handleClose();
        }
    });

    const deleteMutation = useMutation({
        mutationFn: (id) => client.delete(`/security/countries/groups/${id}`),
        onSuccess: () => {
            queryClient.invalidateQueries(['countryGroups']);
        }
    });

    const handleOpen = (group = null) => {
        if (group) {
            setEditingGroup(group);
            setFormData({
                name: group.name,
                description: group.description,
                countries: group.countries,
                color: group.color || '#ff0000'
            });
        } else {
            setEditingGroup(null);
            setFormData({ name: '', description: '', countries: '', color: '#ff0000' });
        }
        setOpen(true);
    };

    const handleClose = () => {
        setOpen(false);
        setEditingGroup(null);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (editingGroup) {
            updateMutation.mutate({ id: editingGroup.id, data: formData });
        } else {
            createMutation.mutate(formData);
        }
    };

    const handleDelete = (id) => {
        if (window.confirm('Delete this group?')) {
            deleteMutation.mutate(id);
        }
    };

    return (
        <Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h5" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <PublicIcon color="primary" /> Country Groups
                </Typography>
                <Button variant="contained" startIcon={<AddIcon />} onClick={() => handleOpen()}>
                    New Group
                </Button>
            </Box>

            <TableContainer component={Paper}>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>Group Name</TableCell>
                            <TableCell>Description</TableCell>
                            <TableCell>Countries</TableCell>
                            <TableCell align="right">Actions</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {isLoading ? (
                            <TableRow><TableCell colSpan={4} align="center">Loading...</TableCell></TableRow>
                        ) : groups?.length === 0 ? (
                            <TableRow><TableCell colSpan={4} align="center">No country groups defined.</TableCell></TableRow>
                        ) : (
                            groups?.map((group) => (
                                <TableRow key={group.id}>
                                    <TableCell>
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: group.color }} />
                                            {group.name}
                                        </Box>
                                    </TableCell>
                                    <TableCell>{group.description}</TableCell>
                                    <TableCell>
                                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                            {group.countries.split(',').filter(c => c).map(code => (
                                                <Chip key={code} label={code} size="small" />
                                            ))}
                                        </Box>
                                    </TableCell>
                                    <TableCell align="right">
                                        <IconButton onClick={() => handleOpen(group)} size="small"><EditIcon /></IconButton>
                                        <IconButton onClick={() => handleDelete(group.id)} size="small" color="error"><DeleteIcon /></IconButton>
                                    </TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </TableContainer>

            <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
                <form onSubmit={handleSubmit}>
                    <DialogTitle>{editingGroup ? 'Edit Group' : 'New Country Group'}</DialogTitle>
                    <DialogContent dividers>
                        <TextField
                            fullWidth label="Group Name" margin="normal"
                            value={formData.name} onChange={e => setFormData({ ...formData, name: e.target.value })}
                            required
                        />
                        <TextField
                            fullWidth label="Description" margin="normal"
                            value={formData.description} onChange={e => setFormData({ ...formData, description: e.target.value })}
                        />
                        <TextField
                            fullWidth label="Countries (ISO Codes, comma separated)" margin="normal"
                            value={formData.countries} onChange={e => setFormData({ ...formData, countries: e.target.value })}
                            helperText="Example: CN, RU, KP, BR"
                        />
                        <TextField
                            fullWidth label="Label Color" margin="normal" type="color"
                            value={formData.color} onChange={e => setFormData({ ...formData, color: e.target.value })}
                        />
                    </DialogContent>
                    <DialogActions>
                        <Button onClick={handleClose}>Cancel</Button>
                        <Button type="submit" variant="contained">Save</Button>
                    </DialogActions>
                </form>
            </Dialog>
        </Box>
    );
};

export default CountryGroups;
