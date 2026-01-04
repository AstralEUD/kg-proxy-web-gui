import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Paper, Typography, TextField, Button, Alert, CircularProgress } from '@mui/material';
import { LockOpen, Shield } from '@mui/icons-material';
import client from '../api/client';

export default function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        try {
            const res = await client.post('/login', { username, password });
            localStorage.setItem('token', res.data.token);
            client.defaults.headers.common['Authorization'] = `Bearer ${res.data.token}`;
            navigate('/');
        } catch (err) {
            setError(err.response?.data?.error || 'Invalid credentials. Default: admin / admin123!');
        }
        setLoading(false);
    };

    return (
        <Box
            sx={{
                minHeight: '100vh',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #0a0a0a 100%)',
            }}
        >
            <Paper
                sx={{
                    p: 5,
                    width: '100%',
                    maxWidth: 420,
                    textAlign: 'center',
                    bgcolor: '#1a1a2e',
                    borderRadius: 4,
                    border: '1px solid #00e5ff30',
                    boxShadow: '0 0 40px #00e5ff20'
                }}
            >
                <Box sx={{ mb: 4 }}>
                    <Shield sx={{ fontSize: 60, color: '#00e5ff', mb: 1 }} />
                    <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#00e5ff' }}>
                        ArmaGuard
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                        DDoS Protection Manager
                    </Typography>
                </Box>

                <form onSubmit={handleLogin}>
                    <TextField
                        fullWidth
                        label="Username"
                        margin="normal"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                '&:hover fieldset': { borderColor: '#00e5ff' },
                                '&.Mui-focused fieldset': { borderColor: '#00e5ff' },
                            }
                        }}
                    />
                    <TextField
                        fullWidth
                        label="Password"
                        type="password"
                        margin="normal"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                '&:hover fieldset': { borderColor: '#00e5ff' },
                                '&.Mui-focused fieldset': { borderColor: '#00e5ff' },
                            }
                        }}
                    />

                    {error && <Alert severity="error" sx={{ mt: 2, textAlign: 'left' }}>{error}</Alert>}

                    <Button
                        fullWidth
                        variant="contained"
                        size="large"
                        type="submit"
                        disabled={loading}
                        startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <LockOpen />}
                        sx={{
                            mt: 3,
                            py: 1.5,
                            background: 'linear-gradient(45deg, #00e5ff, #00b8d4)',
                            color: '#000',
                            fontWeight: 'bold',
                            '&:hover': { background: 'linear-gradient(45deg, #00b8d4, #00e5ff)' }
                        }}
                    >
                        {loading ? 'Signing in...' : 'Sign In'}
                    </Button>
                </form>

                <Typography variant="caption" color="textSecondary" sx={{ display: 'block', mt: 3 }}>
                    Protected by ArmaGuard Security
                </Typography>
            </Paper>
        </Box>
    );
}
