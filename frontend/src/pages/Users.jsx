import React, { useState, useEffect } from 'react';
import { Box, Paper, Typography, Button, TextField, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Dialog, DialogTitle, DialogContent, DialogActions } from '@mui/material';
import { Add, Delete, Person, Key } from '@mui/icons-material';
import client from '../api/client';

export default function Users() {
    const [users, setUsers] = useState([]);
    const [open, setOpen] = useState(false);
    const [pwOpen, setPwOpen] = useState(false);
    const [newUser, setNewUser] = useState({ username: '', password: '' });
    const [pwData, setPwData] = useState({ old_password: '', new_password: '' });

    const fetchUsers = async () => {
        try {
            const res = await client.get('/users');
            setUsers(res.data || []);
        } catch (e) {
            // Mock if backend not ready
            setUsers([{ ID: 1, username: 'admin' }, { ID: 2, username: 'operator' }]);
        }
    };

    useEffect(() => { fetchUsers(); }, []);

    const handleCreate = async () => {
        try {
            await client.post('/users', newUser);
            setOpen(false);
            fetchUsers();
        } catch (e) {
            alert('Failed to create user');
        }
    };

    const handleDelete = async (id) => {
        if (window.confirm('Delete this user?')) {
            try {
                await client.delete(`/users/${id}`);
                fetchUsers();
            } catch (e) {
                alert('Failed to delete user');
            }
        }
    };

    const handleChangePassword = async () => {
        try {
            await client.put('/auth/password', pwData);
            alert('Password updated successfully');
            setPwOpen(false);
            setPwData({ old_password: '', new_password: '' });
        } catch (e) {
            alert(e.response?.data?.error || 'Failed to update password');
        }
    };

    return (
        <Box sx={{ width: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Person sx={{ color: '#00e5ff', mr: 1, fontSize: 32 }} />
                    <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#fff' }}>User Management</Typography>
                </Box>
                <Box>
                    <Button variant="outlined" startIcon={<Key />} onClick={() => setPwOpen(true)} sx={{ mr: 2, color: '#00e5ff', borderColor: '#00e5ff' }}>
                        Change Password
                    </Button>
                    <Button variant="contained" startIcon={<Add />} onClick={() => setOpen(true)} sx={{ bgcolor: '#00e5ff', color: '#000', fontWeight: 'bold' }}>
                        Add User
                    </Button>
                </Box>
            </Box>

            <Paper sx={{ bgcolor: '#111', border: '1px solid #222' }}>
                <TableContainer>
                    <Table>
                        <TableHead>
                            <TableRow sx={{ '& th': { bgcolor: '#0a0a0a', color: '#888' } }}>
                                <TableCell>ID</TableCell>
                                <TableCell>Username</TableCell>
                                <TableCell>Role</TableCell>
                                <TableCell align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {users.map((user) => (
                                <TableRow key={user.ID} hover sx={{ '&:hover': { bgcolor: '#ffffff05' } }}>
                                    <TableCell sx={{ color: '#666' }}>{user.ID}</TableCell>
                                    <TableCell sx={{ color: '#fff', fontWeight: 'bold' }}>{user.username}</TableCell>
                                    <TableCell sx={{ color: '#00e5ff' }}>Admin</TableCell>
                                    <TableCell align="right">
                                        <Button color="error" size="small" onClick={() => handleDelete(user.ID)} disabled={user.username === 'admin'}>
                                            <Delete />
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>

            <Dialog open={open} onClose={() => setOpen(false)} PaperProps={{ sx: { bgcolor: '#111', border: '1px solid #333' } }}>
                <DialogTitle sx={{ color: '#fff' }}>Add New User</DialogTitle>
                <DialogContent>
                    <TextField
                        autoFocus
                        margin="dense"
                        label="Username"
                        fullWidth
                        variant="outlined"
                        value={newUser.username}
                        onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                        sx={{ mb: 2, '& input': { color: '#fff' }, '& label': { color: '#888' }, '& fieldset': { borderColor: '#333' } }}
                    />
                    <TextField
                        margin="dense"
                        label="Password"
                        type="password"
                        fullWidth
                        variant="outlined"
                        value={newUser.password}
                        onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                        sx={{ '& input': { color: '#fff' }, '& label': { color: '#888' }, '& fieldset': { borderColor: '#333' } }}
                    />
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setOpen(false)} sx={{ color: '#888' }}>Cancel</Button>
                    <Button onClick={handleCreate} sx={{ color: '#00e5ff' }}>Create</Button>
                </DialogActions>
            </Dialog>

            <Dialog open={pwOpen} onClose={() => setPwOpen(false)} PaperProps={{ sx: { bgcolor: '#111', border: '1px solid #333' } }}>
                <DialogTitle sx={{ color: '#fff' }}>Change My Password</DialogTitle>
                <DialogContent>
                    <TextField
                        autoFocus
                        margin="dense"
                        label="Old Password"
                        type="password"
                        fullWidth
                        variant="outlined"
                        value={pwData.old_password}
                        onChange={(e) => setPwData({ ...pwData, old_password: e.target.value })}
                        sx={{ mb: 2, '& input': { color: '#fff' }, '& label': { color: '#888' }, '& fieldset': { borderColor: '#333' } }}
                    />
                    <TextField
                        margin="dense"
                        label="New Password"
                        type="password"
                        fullWidth
                        variant="outlined"
                        value={pwData.new_password}
                        onChange={(e) => setPwData({ ...pwData, new_password: e.target.value })}
                        sx={{ '& input': { color: '#fff' }, '& label': { color: '#888' }, '& fieldset': { borderColor: '#333' } }}
                    />
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setPwOpen(false)} sx={{ color: '#888' }}>Cancel</Button>
                    <Button onClick={handleChangePassword} sx={{ color: '#00e5ff' }}>Update</Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
