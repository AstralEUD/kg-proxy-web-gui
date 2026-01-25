import { useState, useEffect } from 'react';
import {
    Box,
    Typography,
    TextField,
    Button,
    Card,
    CardContent,
    CircularProgress,
    Divider,
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableRow,
    IconButton,
    Chip,
    Alert
} from '@mui/material';
import {
    BugReport as BugIcon,
    PlayArrow as PlayIcon,
    Stop as StopIcon,
    Download as DownloadIcon,
    Delete as DeleteIcon,
    Refresh as RefreshIcon
} from '@mui/icons-material';
import client from '../api/client';

const PCAPControl = () => {
    const [status, setStatus] = useState({ is_capturing: false });
    const [files, setFiles] = useState([]);
    const [interfaceName, setInterfaceName] = useState('');
    const [duration, setDuration] = useState(60);
    const [filter, setFilter] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchStatus();
        fetchFiles();
        const interval = setInterval(() => {
            fetchStatus();
        }, 2000);
        return () => clearInterval(interval);
    }, []);

    const fetchStatus = async () => {
        try {
            const res = await client.get('/pcap/status');
            setStatus(res.data);
            if (!res.data.is_capturing && status.is_capturing) {
                // If stopped capturing since last check, refresh files
                fetchFiles();
            }
        } catch (err) {
            console.error("Failed to fetch PCAP status", err);
        }
    };

    const fetchFiles = async () => {
        try {
            const res = await client.get('/pcap/files');
            setFiles(res.data);
        } catch (err) {
            console.error("Failed to fetch PCAP files", err);
        }
    };

    const handleStart = async () => {
        setLoading(true);
        setError(null);
        try {
            await client.post('/pcap/start', {
                interface: interfaceName,
                duration: parseInt(duration),
                filter
            });
            fetchStatus();
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleStop = async () => {
        setLoading(true);
        try {
            await client.post('/pcap/stop');
            fetchStatus();
            fetchFiles();
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (filename) => {
        if (!confirm(`Delete ${filename}?`)) return;
        try {
            await client.delete(`/pcap/files/${filename}`);
            fetchFiles();
        } catch (err) {
            alert(`Failed to delete: ${err.message}`);
        }
    };

    const handleDownload = async (filename) => {
        // Construct download URL
        // Assuming API is at /api
        const url = `${client.defaults.baseURL}/pcap/files/${filename}`;
        window.open(url, '_blank');
    };

    return (
        <Card>
            <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <BugIcon color="warning" /> Packet Capture (PCAP)
                    </Typography>
                    {status.is_capturing && (
                        <Chip
                            icon={<CircularProgress size={16} color="inherit" />}
                            label={`Capturing... ${status.duration}`}
                            color="error"
                            variant="outlined"
                        />
                    )}
                </Box>
                <Divider sx={{ mb: 2 }} />

                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

                <Grid container spacing={2} alignItems="center">
                    <Grid item xs={12} md={3}>
                        <TextField
                            fullWidth
                            label="Interface (Empty=Default)"
                            size="small"
                            value={interfaceName}
                            onChange={(e) => setInterfaceName(e.target.value)}
                            disabled={status.is_capturing}
                        />
                    </Grid>
                    <Grid item xs={12} md={2}>
                        <TextField
                            fullWidth
                            label="Duration (sec)"
                            type="number"
                            size="small"
                            value={duration}
                            onChange={(e) => setDuration(e.target.value)}
                            disabled={status.is_capturing}
                        />
                    </Grid>
                    <Grid item xs={12} md={4}>
                        <TextField
                            fullWidth
                            label="Filter (tcpdump style)"
                            placeholder="udp port 5002"
                            size="small"
                            value={filter}
                            onChange={(e) => setFilter(e.target.value)}
                            disabled={status.is_capturing}
                        />
                    </Grid>
                    <Grid item xs={12} md={3}>
                        {status.is_capturing ? (
                            <Button
                                fullWidth
                                variant="contained"
                                color="error"
                                onClick={handleStop}
                                startIcon={<StopIcon />}
                                disabled={loading}
                            >
                                Stop
                            </Button>
                        ) : (
                            <Button
                                fullWidth
                                variant="contained"
                                color="success"
                                onClick={handleStart}
                                startIcon={<PlayIcon />}
                                disabled={loading}
                            >
                                Start Capture
                            </Button>
                        )}
                    </Grid>
                </Grid>

                <Box sx={{ mt: 3 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                        <Typography variant="subtitle2">Captured Files</Typography>
                        <IconButton size="small" onClick={fetchFiles}><RefreshIcon /></IconButton>
                    </Box>
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell>Filename</TableCell>
                                <TableCell align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {files.length === 0 ? (
                                <TableRow>
                                    <TableCell colSpan={2} align="center">No files found</TableCell>
                                </TableRow>
                            ) : (
                                files.map(file => (
                                    <TableRow key={file}>
                                        <TableCell>{file}</TableCell>
                                        <TableCell align="right">
                                            <IconButton color="primary" onClick={() => handleDownload(file)} title="Download">
                                                <DownloadIcon />
                                            </IconButton>
                                            <IconButton color="error" onClick={() => handleDelete(file)} title="Delete">
                                                <DeleteIcon />
                                            </IconButton>
                                        </TableCell>
                                    </TableRow>
                                ))
                            )}
                        </TableBody>
                    </Table>
                </Box>
            </CardContent>
        </Card>
    );
};

export default PCAPControl;
