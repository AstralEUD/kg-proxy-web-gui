import { useState } from 'react';
import {
    Box,
    Typography,
    TextField,
    Button,
    Grid,
    Card,
    CardContent,
    CircularProgress,
    Divider,
    Chip,
    Alert
} from '@mui/material';
import {
    NetworkCheck as NetworkIcon,
    Route as RouteIcon,
    Timeline as TimelineIcon,
    Speed as SpeedIcon
} from '@mui/icons-material';
import client from '../api/client';
import PCAPControl from '../components/PCAPControl';

const TerminalOutput = ({ output }) => (
    <Box
        sx={{
            bgcolor: '#1e1e1e',
            color: '#00ff00',
            fontFamily: 'monospace',
            p: 2,
            borderRadius: 1,
            minHeight: '200px',
            maxHeight: '400px',
            overflow: 'auto',
            whiteSpace: 'pre-wrap',
            fontSize: '0.9rem',
            border: '1px solid #333'
        }}
    >
        {output || 'Ready...'}
    </Box>
);

const NetworkTools = () => {
    const [pingTarget, setPingTarget] = useState('');
    const [traceTarget, setTraceTarget] = useState('');
    const [pingResult, setPingResult] = useState('');
    const [traceResult, setTraceResult] = useState('');
    const [loadingPing, setLoadingPing] = useState(false);
    const [loadingTrace, setLoadingTrace] = useState(false);
    const [wgStatus, setWgStatus] = useState(null);
    const [loadingWg, setLoadingWg] = useState(false);

    const handlePing = async (e) => {
        e.preventDefault();
        if (!pingTarget) return;

        setLoadingPing(true);
        setPingResult(`Pinging ${pingTarget}...\n`);

        try {
            const res = await client.post('/tools/ping', { target: pingTarget, count: 4 });
            setPingResult(prev => prev + (res.data.success ? res.data.output : `Error: ${res.data.output}`));
        } catch (err) {
            setPingResult(prev => prev + `\nRequest failed: ${err.message}`);
        } finally {
            setLoadingPing(false);
        }
    };

    const handleTraceroute = async (e) => {
        e.preventDefault();
        if (!traceTarget) return;

        setLoadingTrace(true);
        setTraceResult(`Tracing route to ${traceTarget} (may take up to 15s)...\n`);

        try {
            const res = await client.post('/tools/traceroute', { target: traceTarget });
            setTraceResult(prev => prev + (res.data.success ? res.data.output : `Error: ${res.data.output}`));
        } catch (err) {
            setTraceResult(prev => prev + `\nRequest failed: ${err.message}`);
            if (err.response?.status === 504) {
                setTraceResult(prev => prev + `\nTimeout: The request took too long.`);
            }
        } finally {
            setLoadingTrace(false);
        }
    };

    const checkWgConnectivity = async () => {
        setLoadingWg(true);
        try {
            const res = await client.get('/tools/wg-ping');
            setWgStatus(res.data);
        } catch (err) {
            console.error(err);
            setWgStatus({ error: err.message });
        } finally {
            setLoadingWg(false);
        }
    };

    return (
        <Box>
            <Typography variant="h4" sx={{ mb: 4, display: 'flex', alignItems: 'center', gap: 2 }}>
                <NetworkIcon fontSize="large" color="primary" />
                Network Diagnostics
            </Typography>

            <Grid container spacing={3}>
                {/* Ping Tool */}
                <Grid item xs={12} md={6}>
                    <Card sx={{ height: '100%' }}>
                        <CardContent>
                            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <TimelineIcon color="info" /> ICMP Ping
                            </Typography>
                            <Divider sx={{ mb: 2 }} />

                            <form onSubmit={handlePing}>
                                <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                                    <TextField
                                        fullWidth
                                        size="small"
                                        placeholder="IP address or Domain (e.g., 8.8.8.8)"
                                        value={pingTarget}
                                        onChange={(e) => setPingTarget(e.target.value)}
                                        disabled={loadingPing}
                                    />
                                    <Button
                                        variant="contained"
                                        type="submit"
                                        disabled={loadingPing || !pingTarget}
                                        startIcon={loadingPing ? <CircularProgress size={20} /> : <TimelineIcon />}
                                    >
                                        Ping
                                    </Button>
                                </Box>
                            </form>

                            <TerminalOutput output={pingResult} />
                        </CardContent>
                    </Card>
                </Grid>

                {/* Traceroute Tool */}
                <Grid item xs={12} md={6}>
                    <Card sx={{ height: '100%' }}>
                        <CardContent>
                            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <RouteIcon color="secondary" /> Traceroute
                            </Typography>
                            <Divider sx={{ mb: 2 }} />

                            <form onSubmit={handleTraceroute}>
                                <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                                    <TextField
                                        fullWidth
                                        size="small"
                                        placeholder="IP address or Domain"
                                        value={traceTarget}
                                        onChange={(e) => setTraceTarget(e.target.value)}
                                        disabled={loadingTrace}
                                    />
                                    <Button
                                        variant="contained"
                                        color="secondary"
                                        type="submit"
                                        disabled={loadingTrace || !traceTarget}
                                        startIcon={loadingTrace ? <CircularProgress size={20} /> : <RouteIcon />}
                                    >
                                        Trace
                                    </Button>
                                </Box>
                            </form>

                            <TerminalOutput output={traceResult} />
                        </CardContent>
                    </Card>
                </Grid>

                {/* WireGuard Connectivity */}
                <Grid item xs={12}>
                    <Card>
                        <CardContent>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                                <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <SpeedIcon color="success" /> WireGuard Connectivity Check
                                </Typography>
                                <Button
                                    variant="outlined"
                                    onClick={checkWgConnectivity}
                                    disabled={loadingWg}
                                >
                                    {loadingWg ? 'Checking...' : 'Check Status'}
                                </Button>
                            </Box>
                            <Divider sx={{ mb: 2 }} />

                            {wgStatus ? (
                                <Grid container spacing={2}>
                                    {/* Simplified view since backend returns raw status object for now */}
                                    <Grid item xs={12}>
                                        <Box sx={{ p: 2, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                                            <Typography variant="body2" component="pre" sx={{ overflow: 'auto' }}>
                                                {JSON.stringify(wgStatus, null, 2)}
                                            </Typography>
                                        </Box>
                                    </Grid>
                                </Grid>
                            ) : (
                                <Typography variant="body2" color="text.secondary">
                                    Click 'Check Status' to verify Origin connectivity via WireGuard interface.
                                </Typography>
                            )}
                        </CardContent>
                    </Card>
                </Grid>

                {/* PCAP Tool */}
                <Grid item xs={12}>
                    <PCAPControl />
                </Grid>
            </Grid>
        </Box>
    );
};

export default NetworkTools;
