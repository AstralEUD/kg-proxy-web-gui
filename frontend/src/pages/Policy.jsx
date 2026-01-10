import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Box, Typography, Card, CardContent, Grid, Switch, FormControlLabel, Button, Slider, Chip, Divider, TextField, Alert, Snackbar, CircularProgress, FormControl, InputLabel, Select, MenuItem, Tabs, Tab, Paper } from '@mui/material';
import { Shield, Public, GppGood, Bolt, CheckCircle, Settings, Notifications, Build, Save } from '@mui/icons-material';
import client from '../api/client';

function TabPanel(props) {
    const { children, value, index, ...other } = props;
    return (
        <div role="tabpanel" hidden={value !== index} {...other}>
            {value === index && (
                <Box sx={{ py: 3 }}>
                    {children}
                </Box>
            )}
        </div>
    );
}

export default function Policy() {
    const queryClient = useQueryClient();
    const [notification, setNotification] = useState({ open: false, message: '' });
    const [tabValue, setTabValue] = useState(0);

    const allCountries = ["KR", "US", "CN", "JP", "DE", "RU", "BR", "GB", "CA", "AU", "IN", "FR", "ID", "VN"];

    // Fetch settings from backend
    const { data: settings, isLoading } = useQuery({
        queryKey: ['security-settings'],
        queryFn: async () => {
            const res = await client.get('/security/settings');
            // Parse geo_allow_countries from CSV string to array
            const data = res.data;
            return {
                ...data,
                geo_allow_countries: data.geo_allow_countries ? data.geo_allow_countries.split(',') : ['KR']
            };
        },
    });

    // Update mutation
    const updateMutation = useMutation({
        mutationFn: (data) => client.put('/security/settings', data),
        onSuccess: () => {
            queryClient.invalidateQueries(['security-settings']);
            setNotification({ open: true, message: 'Firewall policies applied successfully!' });
        },
        onError: (err) => {
            alert('Error applying policies: ' + (err.response?.data?.error || err.message));
        },
    });

    const handleChange = (name) => (e) => {
        queryClient.setQueryData(['security-settings'], (old) => ({
            ...old,
            [name]: e.target.checked
        }));
    };

    const handleSlider = (name) => (e, val) => {
        queryClient.setQueryData(['security-settings'], (old) => ({
            ...old,
            [name]: val
        }));
    };

    const handleCountryToggle = (code) => {
        queryClient.setQueryData(['security-settings'], (old) => {
            const list = old.geo_allow_countries.includes(code)
                ? old.geo_allow_countries.filter(c => c !== code)
                : [...old.geo_allow_countries, code];
            return { ...old, geo_allow_countries: list };
        });
    };

    const handleApply = () => {
        if (!settings) return;
        updateMutation.mutate(settings);
    };

    if (isLoading) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <CircularProgress />
            </Box>
        );
    }

    if (!settings) {
        return <Typography color="error">Failed to load settings</Typography>;
    }

    return (
        <Box sx={{ width: '100%' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <Shield sx={{ color: '#00e5ff', mr: 1, fontSize: 32 }} />
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#fff' }}>Policy & Firewall</Typography>
            </Box>

            <Paper sx={{ bgcolor: '#0a0a0a', borderBottom: 1, borderColor: '#333' }}>
                <Tabs
                    value={tabValue}
                    onChange={(e, v) => setTabValue(v)}
                    textColor="secondary"
                    indicatorColor="secondary"
                    sx={{ '& .MuiTab-root': { color: '#888', '&.Mui-selected': { color: '#00e5ff' } } }}
                >
                    <Tab label="General" icon={<GppGood />} iconPosition="start" />
                    <Tab label="Advanced" icon={<Bolt />} iconPosition="start" />
                    <Tab label="Management" icon={<Settings />} iconPosition="start" />
                </Tabs>
            </Paper>

            {/* Tab 1: General (Global Protection & GeoIP) */}
            <TabPanel value={tabValue} index={0}>
                <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                            <CardContent>
                                <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                    <GppGood sx={{ mr: 1, color: '#00c853' }} /> Global Protection
                                </Typography>
                                <FormControlLabel control={<Switch checked={settings.global_protection} onChange={handleChange('global_protection')} color="secondary" />} label="Enable DDoS Protection Engine" sx={{ color: '#fff', mb: 1, display: 'block' }} />
                                <FormControlLabel control={<Switch checked={settings.syn_cookies} onChange={handleChange('syn_cookies')} color="default" />} label="Enable SYN Cookies" sx={{ color: '#ccc', mb: 2, display: 'block' }} />

                                <Divider sx={{ my: 2, bgcolor: '#333' }} />

                                <Typography variant="subtitle2" sx={{ color: '#888', mb: 1 }}>Flood Protection Sensitivity</Typography>
                                <Box sx={{ px: 2, py: 1 }}>
                                    <Slider
                                        value={settings.protection_level}
                                        onChange={handleSlider('protection_level')}
                                        step={1} marks min={0} max={2}
                                        valueLabelDisplay="off"
                                        sx={{ color: settings.protection_level === 2 ? '#f50057' : '#00e5ff' }}
                                    />
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', color: '#666', fontSize: 12 }}>
                                        <span>Low</span>
                                        <span>Standard</span>
                                        <span style={{ color: '#f50057' }}>High (Recommended)</span>
                                    </Box>
                                </Box>
                            </CardContent>
                        </Card>
                    </Grid>

                    <Grid item xs={12} md={6}>
                        <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                            <CardContent>
                                <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                    <Public sx={{ mr: 1, color: '#00e5ff' }} /> Geo-IP Whitelist
                                </Typography>

                                <Typography variant="subtitle2" sx={{ color: '#888', mb: 1 }}>Allowed Countries (Others Blocked)</Typography>
                                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
                                    {allCountries.map(code => (
                                        <Chip
                                            key={code}
                                            label={code}
                                            onClick={() => handleCountryToggle(code)}
                                            color={settings.geo_allow_countries.includes(code) ? "success" : "default"}
                                            variant={settings.geo_allow_countries.includes(code) ? "filled" : "outlined"}
                                            icon={settings.geo_allow_countries.includes(code) ? <CheckCircle /> : undefined}
                                            sx={{ cursor: 'pointer', borderColor: '#444', color: '#fff' }}
                                        />
                                    ))}
                                </Box>

                                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                    <FormControlLabel control={<Switch checked={settings.block_vpn} onChange={handleChange('block_vpn')} color="error" />} label="Block Known VPN/Proxy Ranges" sx={{ color: '#ccc' }} />
                                    <FormControlLabel control={<Switch checked={settings.block_tor} onChange={handleChange('block_tor')} color="error" />} label="Block TOR Exit Nodes" sx={{ color: '#ccc' }} />
                                </Box>

                                <Divider sx={{ my: 2, bgcolor: '#333' }} />

                                <FormControlLabel
                                    control={<Switch checked={settings.steam_query_bypass} onChange={handleChange('steam_query_bypass')} color="success" />}
                                    label={
                                        <Box>
                                            <Typography variant="body1">Allow Steam Server Queries (Global)</Typography>
                                            <Typography variant="caption" sx={{ color: '#888' }}>
                                                Bypasses Geo-IP for server browser listings (A2S_INFO).
                                            </Typography>
                                        </Box>
                                    }
                                    sx={{ color: '#fff', alignItems: 'flex-start', ml: 0 }}
                                />
                            </CardContent>
                        </Card>
                    </Grid>
                </Grid>
            </TabPanel>

            {/* Tab 2: Advanced (Next-Gen & XDP) */}
            <TabPanel value={tabValue} index={1}>
                <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                            <CardContent>
                                <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                    <Bolt sx={{ mr: 1, color: '#00e5ff' }} /> Next-Gen Technologies
                                </Typography>
                                <Card variant="outlined" sx={{ mb: 2, bgcolor: settings.ebpf_enabled ? '#00e5ff10' : 'transparent', borderColor: settings.ebpf_enabled ? '#00e5ff' : '#333' }}>
                                    <CardContent sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 1.5, '&:last-child': { pb: 1.5 } }}>
                                        <Box>
                                            <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 'bold' }}>eBPF XDP Filter</Typography>
                                            <Typography variant="caption" sx={{ color: '#888' }}>Kernel-level high-performance packet filtering.</Typography>
                                        </Box>
                                        <Switch checked={settings.ebpf_enabled} onChange={handleChange('ebpf_enabled')} color="info" />
                                    </CardContent>
                                </Card>
                                <Card variant="outlined" sx={{ mb: 3, bgcolor: settings.smart_banning ? '#00c85310' : 'transparent', borderColor: settings.smart_banning ? '#00c853' : '#333' }}>
                                    <CardContent sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 1.5, '&:last-child': { pb: 1.5 } }}>
                                        <Box>
                                            <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 'bold' }}>Geo-IP Smart Banning</Typography>
                                            <Typography variant="caption" sx={{ color: '#888' }}>AI-driven dynamic regional blocking.</Typography>
                                        </Box>
                                        <Switch checked={settings.smart_banning} onChange={handleChange('smart_banning')} color="success" />
                                    </CardContent>
                                </Card>

                                <Divider sx={{ my: 2, bgcolor: '#333' }} />

                                <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 'bold', mb: 1, display: 'flex', alignItems: 'center' }}>
                                    <Public sx={{ mr: 1, fontSize: 18 }} /> MaxMind GeoLite2 License Key
                                </Typography>
                                <TextField
                                    fullWidth
                                    size="small"
                                    type="password"
                                    placeholder="Enter License Key"
                                    value={settings.maxmind_license_key || ''}
                                    onChange={(e) => {
                                        queryClient.setQueryData(['security-settings'], (old) => ({
                                            ...old,
                                            maxmind_license_key: e.target.value
                                        }));
                                    }}
                                    sx={{ bgcolor: '#0a0a0a', '& .MuiOutlinedInput-root': { color: '#fff' } }}
                                />
                                <Typography variant="caption" sx={{ color: '#666', display: 'block', mt: 1 }}>
                                    Required for accurate GeoIP banning.
                                </Typography>
                            </CardContent>
                        </Card>
                    </Grid>

                    <Grid item xs={12} md={6}>
                        <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                            <CardContent>
                                <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                    <Bolt sx={{ mr: 1, color: '#ff9800' }} /> XDP Advanced Settings
                                </Typography>

                                <Card variant="outlined" sx={{ mb: 3, bgcolor: settings.xdp_hard_blocking ? '#ff980010' : 'transparent', borderColor: settings.xdp_hard_blocking ? '#ff9800' : '#333' }}>
                                    <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                                        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                            <Box>
                                                <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 'bold' }}>Hard Blocking Mode</Typography>
                                                <Typography variant="caption" sx={{ color: '#888' }}>Drop packets at kernel level (Immediate)</Typography>
                                            </Box>
                                            <Switch checked={settings.xdp_hard_blocking || false} onChange={handleChange('xdp_hard_blocking')} color="warning" />
                                        </Box>
                                        {settings.xdp_hard_blocking && (
                                            <Alert severity="warning" sx={{ mt: 1, py: 0, '& .MuiAlert-message': { fontSize: '0.8rem' } }}>
                                                GeoIP violations are dropped instantly in Kernel.
                                            </Alert>
                                        )}
                                    </CardContent>
                                </Card>

                                <Typography variant="subtitle2" sx={{ color: '#888', mb: 1 }}>Per-IP Rate Limit (PPS)</Typography>
                                <Box sx={{ px: 2, mb: 2 }}>
                                    <Slider
                                        value={settings.xdp_rate_limit_pps || 0}
                                        onChange={handleSlider('xdp_rate_limit_pps')}
                                        min={0} max={100000} step={1000}
                                        valueLabelDisplay="auto"
                                        marks={[{ value: 0, label: 'Off' }, { value: 30000, label: '30K' }, { value: 100000, label: '100K' }]}
                                        sx={{ color: '#ff9800' }}
                                    />
                                    <Typography variant="caption" sx={{ color: '#666', display: 'block', mt: 1, textAlign: 'center' }}>
                                        {settings.xdp_rate_limit_pps === 0 ? 'Rate limiting disabled' : `Max ${(settings.xdp_rate_limit_pps || 0).toLocaleString()} PPS per IP`}
                                    </Typography>
                                </Box>
                            </CardContent>
                        </Card>
                    </Grid>
                </Grid>
            </TabPanel>

            {/* Tab 3: Management */}
            <TabPanel value={tabValue} index={2}>
                <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                            <CardContent>
                                <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                    <Notifications sx={{ mr: 1, color: '#fff' }} /> Discord Notifications
                                </Typography>
                                <TextField
                                    fullWidth
                                    label="Discord Webhook URL"
                                    value={settings.discord_webhook_url || ''}
                                    onChange={(e) => queryClient.setQueryData(['security-settings'], old => ({ ...old, discord_webhook_url: e.target.value }))}
                                    placeholder="https://discord.com/api/webhooks/..."
                                    size="small"
                                    sx={{ mb: 2, bgcolor: '#0a0a0a', '& .MuiOutlinedInput-root': { color: '#fff' }, '& .MuiInputLabel-root': { color: '#888' } }}
                                />
                                <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                                    <FormControlLabel control={<Switch checked={settings.alert_on_attack} onChange={handleChange('alert_on_attack')} color="error" />} label="Attack Alerts" sx={{ color: '#fff' }} />
                                    <FormControlLabel control={<Switch checked={settings.alert_on_block || false} onChange={handleChange('alert_on_block')} color="warning" />} label="Block Alerts" sx={{ color: '#fff' }} />
                                </Box>
                                <Button
                                    variant="outlined" color="info" fullWidth
                                    onClick={async () => {
                                        try {
                                            await client.post('/webhook/test');
                                            setNotification({ open: true, message: 'Test notification sent!' });
                                        } catch (err) {
                                            alert('Test failed: ' + (err.response?.data?.error || err.message));
                                        }
                                    }}
                                    disabled={!settings.discord_webhook_url}
                                >
                                    Send Test Notification
                                </Button>
                            </CardContent>
                        </Card>
                    </Grid>

                    <Grid item xs={12} md={6}>
                        <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                            <CardContent>
                                <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                    <Save sx={{ mr: 1, color: '#fff' }} /> Backup & Restore
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                                    <Button
                                        variant="contained" color="primary" fullWidth
                                        onClick={async () => {
                                            try {
                                                const res = await client.get('/backup/export');
                                                const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
                                                const url = URL.createObjectURL(blob);
                                                const a = document.createElement('a');
                                                a.href = url;
                                                a.download = `kg-proxy-backup-${new Date().toISOString().slice(0, 10)}.json`;
                                                a.click();
                                                URL.revokeObjectURL(url);
                                                setNotification({ open: true, message: 'Export successful!' });
                                            } catch (err) {
                                                alert('Export failed: ' + err.message);
                                            }
                                        }}
                                    >
                                        Export Config
                                    </Button>
                                    <Button
                                        variant="outlined" color="warning" fullWidth component="label"
                                    >
                                        Import Config
                                        <input
                                            type="file" accept=".json" hidden
                                            onChange={async (e) => {
                                                const file = e.target.files[0];
                                                if (!file || !confirm('Overwrite existing settings?')) return;
                                                try {
                                                    const text = await file.text();
                                                    const data = JSON.parse(text);
                                                    await client.post('/backup/import', data);
                                                    queryClient.invalidateQueries();
                                                    setNotification({ open: true, message: 'Import successful!' });
                                                } catch (err) {
                                                    alert('Import failed: ' + err.message);
                                                }
                                            }}
                                        />
                                    </Button>
                                </Box>

                                <Divider sx={{ my: 2, bgcolor: '#333' }} />

                                <Typography variant="subtitle2" sx={{ color: '#fff', mb: 1, display: 'flex', alignItems: 'center' }}>
                                    <Build sx={{ mr: 1, fontSize: 18 }} /> Maintenance (모든 차단 해제)
                                </Typography>

                                {/* Maintenance Mode Status */}
                                {settings.maintenance_until && new Date(settings.maintenance_until) > new Date() && (
                                    <Alert severity="warning" sx={{ mb: 2 }}>
                                        🔧 유지보수 모드 활성화 - {new Date(settings.maintenance_until).toLocaleTimeString()} 까지 모든 차단 비활성화
                                    </Alert>
                                )}

                                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
                                    {[
                                        { label: '15분', minutes: 15 },
                                        { label: '30분', minutes: 30 },
                                        { label: '1시간', minutes: 60 },
                                        { label: '2시간', minutes: 120 },
                                    ].map(opt => (
                                        <Button
                                            key={opt.minutes}
                                            variant="contained"
                                            size="small"
                                            onClick={() => {
                                                const until = new Date(Date.now() + opt.minutes * 60 * 1000);
                                                queryClient.setQueryData(['security-settings'], old => ({
                                                    ...old,
                                                    maintenance_until: until.toISOString()
                                                }));
                                            }}
                                            sx={{ bgcolor: '#ff9800', '&:hover': { bgcolor: '#f57c00' } }}
                                        >
                                            {opt.label}
                                        </Button>
                                    ))}
                                    <Button
                                        variant="outlined"
                                        size="small"
                                        color="error"
                                        onClick={() => {
                                            queryClient.setQueryData(['security-settings'], old => ({
                                                ...old,
                                                maintenance_until: null
                                            }));
                                        }}
                                    >
                                        해제
                                    </Button>
                                </Box>

                                <Divider sx={{ my: 2, bgcolor: '#333' }} />

                                <Box sx={{ display: 'flex', gap: 1 }}>
                                    <FormControl fullWidth size="small" sx={{ bgcolor: '#0a0a0a' }}>
                                        <InputLabel sx={{ color: '#888' }}>Stats Reset</InputLabel>
                                        <Select
                                            value={settings.traffic_stats_reset_interval || 0}
                                            label="Stats Reset"
                                            onChange={(e) => queryClient.setQueryData(['security-settings'], old => ({ ...old, traffic_stats_reset_interval: e.target.value }))}
                                            sx={{ color: '#fff', '& .MuiOutlinedInput-notchedOutline': { borderColor: '#444' } }}
                                        >
                                            <MenuItem value={0}>Disabled</MenuItem>
                                            <MenuItem value={1}>1 Hour</MenuItem>
                                            <MenuItem value={24}>24 Hours</MenuItem>
                                        </Select>
                                    </FormControl>
                                    <Button
                                        variant="outlined" color="error"
                                        onClick={async () => {
                                            if (confirm('Reset all traffic stats?')) {
                                                await client.post('/traffic/reset');
                                                setNotification({ open: true, message: 'Stats reset!' });
                                            }
                                        }}
                                    >
                                        Reset
                                    </Button>
                                </Box>
                            </CardContent>
                        </Card>
                    </Grid>
                </Grid>
            </TabPanel>

            <Box sx={{ mt: 4 }}>
                <Button
                    fullWidth variant="contained" size="large"
                    onClick={handleApply}
                    disabled={updateMutation.isPending}
                    sx={{ bgcolor: '#f50057', color: '#fff', fontWeight: 'bold', py: 2, fontSize: '1.2rem', '&:hover': { bgcolor: '#c51162' } }}
                >
                    {updateMutation.isPending ? 'APPLYING...' : 'APPLY ALL CHANGES'}
                </Button>
            </Box>

            <Snackbar open={notification.open} autoHideDuration={6000} onClose={() => setNotification({ ...notification, open: false })}>
                <Alert onClose={() => setNotification({ ...notification, open: false })} severity="success" sx={{ width: '100%' }}>
                    {notification.message}
                </Alert>
            </Snackbar>
        </Box>
    );
}
