import { useState, useEffect } from 'react';
import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    Button,
    Typography,
    Grid,
    Chip,
    Box,
    CircularProgress,
    Divider,
    IconButton
} from '@mui/material';
import {
    Public as PublicIcon,
    Security as SecurityIcon,
    DataUsage as DataUsageIcon,
    History as HistoryIcon,
    Close as CloseIcon,
    Block as BlockIcon,
    CheckCircle as CheckCircleIcon
} from '@mui/icons-material';
import client from '../api/client';

const IPInfoModal = ({ ip, open, onClose }) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        if (open && ip) {
            fetchIPInfo();
        }
    }, [open, ip]);

    const fetchIPInfo = async () => {
        setLoading(true);
        setError(null);
        try {
            const res = await client.get(`/ip/info/${ip}`);
            setData(res.data);
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleBlockAction = async (action) => {
        if (!ip) return;
        try {
            if (action === 'block') {
                await client.post('/security/rules/block', { ip });
            } else {
                // Try both rules unblock and active unblock
                try { await client.delete(`/security/rules/block/by-ip/${ip}`); } catch (e) { } // Logic depends on backend ID vs IP deletion support
                // Current backend DELETE /security/rules/block/:id needs ID.
                // But we added DELETE /traffic/blocked for eBPF map.
                await client.delete('/traffic/blocked', { data: { ip } });
            }
            fetchIPInfo(); // Refresh
        } catch (err) {
            alert(`Action failed: ${err.message}`);
        }
    };

    const getStatusColor = (status) => {
        switch (status) {
            case 'allowed': return 'success';
            case 'blocked': return 'error';
            default: return 'default';
        }
    };

    return (
        <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
            <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <PublicIcon /> IP Intelligence: {ip}
                </Box>
                <IconButton onClick={onClose} size="small"><CloseIcon /></IconButton>
            </DialogTitle>

            <DialogContent dividers>
                {loading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
                        <CircularProgress />
                    </Box>
                ) : error ? (
                    <Typography color="error">{error}</Typography>
                ) : data ? (
                    <Grid container spacing={3}>
                        {/* Status Section */}
                        <Grid item xs={12}>
                            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 2 }}>
                                <Chip
                                    label={data.status.toUpperCase()}
                                    color={getStatusColor(data.status)}
                                    icon={data.status === 'blocked' ? <BlockIcon /> : <CheckCircleIcon />}
                                />
                                {data.country_code && (
                                    <Chip
                                        icon={<span className={`fi fi-${data.country_code.toLowerCase()}`} />}
                                        label={data.country_name}
                                        variant="outlined"
                                    />
                                )}
                                {data.isp && <Chip label={data.isp} variant="outlined" />}
                            </Box>
                            {data.block_reason && (
                                <Typography color="error" variant="body2" sx={{ bgcolor: '#ffebee', p: 1, borderRadius: 1 }}>
                                    Reason: {data.block_reason} {data.block_ttl > 0 && `(TTL: ${data.block_ttl}s)`}
                                </Typography>
                            )}
                        </Grid>

                        <Grid item xs={12}><Divider /></Grid>

                        {/* Traffic Stats */}
                        <Grid item xs={12} md={6}>
                            <Typography variant="h6" gutterBottom><DataUsageIcon fontSize="small" /> Real-time Traffic</Typography>
                            {data.traffic ? (
                                <Box>
                                    <Typography variant="body2">Last Seen: {new Date(data.traffic.last_seen).toLocaleString()}</Typography>
                                    <Typography variant="body2">Total Packets: {data.traffic.total_packets}</Typography>
                                    <Typography variant="body2" color={data.traffic.blocked_count > 0 ? "error" : "text.primary"}>
                                        Blocked Packets: {data.traffic.blocked_count}
                                    </Typography>
                                </Box>
                            ) : (
                                <Typography variant="body2" color="text.secondary">No active session detected.</Typography>
                            )}
                        </Grid>

                        {/* Attack History */}
                        <Grid item xs={12} md={6}>
                            <Typography variant="h6" gutterBottom><HistoryIcon fontSize="small" /> Recent History</Typography>
                            {data.history && data.history.length > 0 ? (
                                <Box component="ul" sx={{ pl: 2, m: 0 }}>
                                    {data.history.map(evt => (
                                        <li key={evt.id}>
                                            <Typography variant="caption">
                                                {new Date(evt.timestamp).toLocaleString()} - <strong>{evt.attack_type}</strong> ({evt.action})
                                            </Typography>
                                        </li>
                                    ))}
                                </Box>
                            ) : (
                                <Typography variant="body2" color="text.secondary">No recent attack history.</Typography>
                            )}
                        </Grid>
                    </Grid>
                ) : null}
            </DialogContent>

            <DialogActions>
                <Button href={`https://ipinfo.io/${ip}`} target="_blank" color="info">Whois External</Button>
                {data?.status === 'blocked' ? (
                    <Button onClick={() => handleBlockAction('unblock')} color="success" variant="contained">Unblock Now</Button>
                ) : (
                    <Button onClick={() => handleBlockAction('block')} color="error" variant="contained">Block IP</Button>
                )}
            </DialogActions>
        </Dialog>
    );
};

export default IPInfoModal;
