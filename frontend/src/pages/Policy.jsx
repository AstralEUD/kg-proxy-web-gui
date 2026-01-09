import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Box, Typography, Card, CardContent, Grid, Switch, FormControlLabel, Button, Slider, Chip, Divider, TextField, Alert, Snackbar, CircularProgress, FormControl, InputLabel, Select, MenuItem } from '@mui/material';
import { Shield, Public, GppGood, Bolt, CheckCircle } from '@mui/icons-material';
import client from '../api/client';

export default function Policy() {
    const queryClient = useQueryClient();
    const [notification, setNotification] = useState({ open: false, message: '' });

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

            <Grid container spacing={3}>
                {/* 1. Global Protection & Sensitivity */}
                <Grid item xs={12} md={6}>
                    <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                <GppGood sx={{ mr: 1, color: '#00c853' }} /> Global Protection
                            </Typography>
                            <FormControlLabel control={<Switch checked={settings.global_protection} onChange={handleChange('global_protection')} color="secondary" />} label="Enable DDoS Protection Engine" sx={{ color: '#fff' }} />
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
                            <Divider sx={{ my: 2, bgcolor: '#333' }} />
                            <FormControlLabel control={<Switch checked={settings.syn_cookies} onChange={handleChange('syn_cookies')} color="default" />} label="Enable SYN Cookies" sx={{ color: '#ccc' }} />
                        </CardContent>
                    </Card>
                </Grid>

                {/* 2. Geo Whitelisting */}
                <Grid item xs={12} md={6}>
                    <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                <Public sx={{ mr: 1, color: '#00e5ff' }} /> Geo-IP Whitelist (Allow Only)
                            </Typography>

                            <Typography variant="subtitle2" sx={{ color: '#888', mb: 1 }}>Select countries to <span style={{ color: '#00c853', fontWeight: 'bold' }}>ALLOW</span>. All others will be blocked.</Typography>
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

                            <FormControlLabel control={<Switch checked={settings.block_vpn} onChange={handleChange('block_vpn')} color="error" />} label="Block Known VPN/Proxy Ranges" sx={{ color: '#ccc' }} />
                            <FormControlLabel control={<Switch checked={settings.block_tor} onChange={handleChange('block_tor')} color="error" />} label="Block TOR Exit Nodes" sx={{ color: '#ccc' }} />
                            <Divider sx={{ my: 2, bgcolor: '#333' }} />
                            <FormControlLabel
                                control={<Switch checked={settings.steam_query_bypass} onChange={handleChange('steam_query_bypass')} color="success" />}
                                label={
                                    <Box>
                                        <Typography variant="body1">Allow Steam Server Queries (Global)</Typography>
                                        <Typography variant="caption" sx={{ color: '#888' }}>
                                            Bypasses Geo-IP for server browser listings (A2S_INFO). <br />
                                            Required for your server to appear in the global server list.
                                        </Typography>
                                    </Box>
                                }
                                sx={{ color: '#fff', alignItems: 'flex-start', ml: 0 }}
                            />
                        </CardContent>
                    </Card>
                </Grid>

                {/* (Removed: Access Control Rules - now in dedicated SecurityRules page) */}

                {/* 3. Next-Gen Tech */}
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
                            <Card variant="outlined" sx={{ bgcolor: settings.smart_banning ? '#00c85310' : 'transparent', borderColor: settings.smart_banning ? '#00c853' : '#333' }}>
                                <CardContent sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 1.5, '&:last-child': { pb: 1.5 } }}>
                                    <Box>
                                        <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 'bold' }}>Geo-IP Smart Banning</Typography>
                                        <Typography variant="caption" sx={{ color: '#888' }}>AI-driven dynamic regional blocking.</Typography>
                                    </Box>
                                    <Switch checked={settings.smart_banning} onChange={handleChange('smart_banning')} color="success" />
                                </CardContent>
                            </Card>

                            <Divider sx={{ my: 2, bgcolor: '#333' }} />

                            {/* MaxMind License Key */}
                            <Box sx={{ mb: 1 }}>
                                <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                                    <Public sx={{ mr: 1, fontSize: 18, color: '#00e5ff' }} />
                                    MaxMind GeoLite2 License Key
                                </Typography>
                                <Typography variant="caption" sx={{ color: '#888', display: 'block', mb: 1 }}>
                                    정확한 GeoIP 차단을 위해 MaxMind 라이선스 키가 필요합니다.
                                    <span style={{ color: '#00c853' }}> 무료</span>로 발급받을 수 있습니다.
                                </Typography>
                                <Alert severity="info" sx={{ mb: 2, bgcolor: '#001e3c', '& .MuiAlert-icon': { color: '#00e5ff' } }}>
                                    <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>라이선스 키 발급 방법</Typography>
                                    <Typography variant="caption" component="div">
                                        1. <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener noreferrer" style={{ color: '#90caf9' }}>maxmind.com/en/geolite2/signup</a> 접속<br />
                                        2. 무료 계정 생성 (이메일 인증 필요)<br />
                                        3. 로그인 후 "Manage License Keys" → "Generate new license key" 클릭<br />
                                        4. 생성된 키를 아래에 입력
                                    </Typography>
                                </Alert>
                                <TextField
                                    fullWidth
                                    size="small"
                                    type="password"
                                    placeholder="Enter MaxMind License Key"
                                    value={settings.maxmind_license_key || ''}
                                    onChange={(e) => {
                                        queryClient.setQueryData(['security-settings'], (old) => ({
                                            ...old,
                                            maxmind_license_key: e.target.value
                                        }));
                                    }}
                                    sx={{ bgcolor: '#0a0a0a', '& .MuiOutlinedInput-root': { color: '#fff' } }}
                                />
                            </Box>

                            <Divider sx={{ my: 2, bgcolor: '#333' }} />

                            {/* Traffic Stats Maintenance */}
                            <Box sx={{ mb: 1 }}>
                                <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 'bold', display: 'flex', alignItems: 'center', mb: 1 }}>
                                    <Bolt sx={{ mr: 1, fontSize: 18, color: '#00e5ff' }} />
                                    Traffic Statistics Maintenance
                                </Typography>

                                <Grid container spacing={2} alignItems="center">
                                    <Grid item xs={8}>
                                        <FormControl fullWidth size="small" sx={{ bgcolor: '#0a0a0a' }}>
                                            <InputLabel sx={{ color: '#888' }}>Auto-Reset Interval</InputLabel>
                                            <Select
                                                value={settings.traffic_stats_reset_interval || 0}
                                                label="Auto-Reset Interval"
                                                onChange={(e) => {
                                                    queryClient.setQueryData(['security-settings'], (old) => ({
                                                        ...old,
                                                        traffic_stats_reset_interval: e.target.value
                                                    }));
                                                }}
                                                sx={{ color: '#fff', '& .MuiOutlinedInput-notchedOutline': { borderColor: '#444' } }}
                                            >
                                                <MenuItem value={0}>Disabled</MenuItem>
                                                <MenuItem value={1}>Every 1 Hour</MenuItem>
                                                <MenuItem value={6}>Every 6 Hours</MenuItem>
                                                <MenuItem value={12}>Every 12 Hours</MenuItem>
                                                <MenuItem value={24}>Every 24 Hours</MenuItem>
                                            </Select>
                                        </FormControl>
                                    </Grid>
                                    <Grid item xs={4}>
                                        <Button
                                            variant="outlined"
                                            color="warning"
                                            fullWidth
                                            onClick={async () => {
                                                if (confirm('Are you sure you want to reset all traffic statistics? This cannot be undone.')) {
                                                    try {
                                                        await client.post('/traffic/reset');
                                                        setNotification({ open: true, message: 'Traffic statistics reset successfully' });
                                                    } catch (err) {
                                                        alert('Failed to reset: ' + err.message);
                                                    }
                                                }
                                            }}
                                        >
                                            Reset Now
                                        </Button>
                                    </Grid>
                                </Grid>
                            </Box>
                        </CardContent>
                    </Card>
                </Grid>

                {/* 5. XDP Advanced Settings */}
                <Grid item xs={12} md={6}>
                    <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                <Bolt sx={{ mr: 1, color: '#ff9800' }} /> XDP Advanced Settings
                            </Typography>

                            <Card variant="outlined" sx={{ mb: 2, bgcolor: settings.xdp_hard_blocking ? '#ff980010' : 'transparent', borderColor: settings.xdp_hard_blocking ? '#ff9800' : '#333' }}>
                                <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                        <Box>
                                            <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 'bold' }}>Hard Blocking Mode</Typography>
                                            <Typography variant="caption" sx={{ color: '#888' }}>Drop packets at kernel level (faster, more aggressive)</Typography>
                                        </Box>
                                        <Switch checked={settings.xdp_hard_blocking || false} onChange={handleChange('xdp_hard_blocking')} color="warning" />
                                    </Box>
                                    {settings.xdp_hard_blocking && (
                                        <Alert severity="warning" sx={{ mt: 1, py: 0 }}>GeoIP 위반 트래픽이 커널에서 즉시 폐기됩니다.</Alert>
                                    )}
                                </CardContent>
                            </Card>

                            <Typography variant="subtitle2" sx={{ color: '#888', mb: 1 }}>Per-IP Rate Limit (PPS)</Typography>
                            <Box sx={{ px: 2 }}>
                                <Slider
                                    value={settings.xdp_rate_limit_pps || 0}
                                    onChange={handleSlider('xdp_rate_limit_pps')}
                                    min={0}
                                    max={100000}
                                    step={1000}
                                    valueLabelDisplay="auto"
                                    marks={[
                                        { value: 0, label: 'Off' },
                                        { value: 30000, label: '30K' },
                                        { value: 100000, label: '100K' }
                                    ]}
                                    sx={{ color: '#ff9800' }}
                                />
                                <Typography variant="caption" sx={{ color: '#666' }}>
                                    {settings.xdp_rate_limit_pps === 0 ? 'Rate limiting disabled' : `Max ${(settings.xdp_rate_limit_pps || 0).toLocaleString()} packets/second per IP`}
                                </Typography>
                            </Box>
                        </CardContent>
                    </Card>
                </Grid>

                {/* 6. Discord Webhook Notifications */}
                <Grid item xs={12} md={6}>
                    <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                🔔 Discord Webhook Notifications
                            </Typography>

                            <TextField
                                fullWidth
                                label="Discord Webhook URL"
                                value={settings.discord_webhook_url || ''}
                                onChange={(e) => queryClient.setQueryData(['security-settings'], old => ({ ...old, discord_webhook_url: e.target.value }))}
                                placeholder="https://discord.com/api/webhooks/..."
                                size="small"
                                sx={{ mb: 2, bgcolor: '#0a0a0a', '& .MuiOutlinedInput-root': { '& fieldset': { borderColor: '#333' } }, '& .MuiInputLabel-root': { color: '#888' }, '& .MuiInputBase-input': { color: '#fff' } }}
                            />

                            <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                                <FormControlLabel
                                    control={<Switch checked={settings.alert_on_attack} onChange={handleChange('alert_on_attack')} color="error" />}
                                    label="Attack Alerts"
                                    sx={{ color: '#fff' }}
                                />
                                <FormControlLabel
                                    control={<Switch checked={settings.alert_on_block || false} onChange={handleChange('alert_on_block')} color="warning" />}
                                    label="Block Alerts"
                                    sx={{ color: '#fff' }}
                                />
                            </Box>

                            <Button
                                variant="outlined"
                                color="info"
                                onClick={async () => {
                                    try {
                                        await client.post('/webhook/test');
                                        setNotification({ open: true, message: 'Test notification sent to Discord!' });
                                    } catch (err) {
                                        alert('Failed to send test: ' + (err.response?.data?.error || err.message));
                                    }
                                }}
                                disabled={!settings.discord_webhook_url}
                            >
                                Send Test Notification
                            </Button>
                        </CardContent>
                    </Card>
                </Grid>

                {/* 7. Backup & Restore */}
                <Grid item xs={12} md={6}>
                    <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                💾 Backup & Restore
                            </Typography>

                            <Typography variant="body2" sx={{ color: '#888', mb: 2 }}>
                                Export all configuration (Origins, Services, Security Settings, IP Rules) to a JSON file for backup or migration.
                            </Typography>

                            <Box sx={{ display: 'flex', gap: 2 }}>
                                <Button
                                    variant="contained"
                                    color="primary"
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
                                            setNotification({ open: true, message: 'Configuration exported successfully!' });
                                        } catch (err) {
                                            alert('Export failed: ' + err.message);
                                        }
                                    }}
                                >
                                    Export Config
                                </Button>
                                <Button
                                    variant="outlined"
                                    color="warning"
                                    component="label"
                                >
                                    Import Config
                                    <input
                                        type="file"
                                        accept=".json"
                                        hidden
                                        onChange={async (e) => {
                                            const file = e.target.files[0];
                                            if (!file) return;
                                            if (!confirm('This will import the backup and may overwrite existing data. Continue?')) return;
                                            try {
                                                const text = await file.text();
                                                const data = JSON.parse(text);
                                                await client.post('/backup/import', data);
                                                queryClient.invalidateQueries();
                                                setNotification({ open: true, message: 'Configuration imported successfully!' });
                                            } catch (err) {
                                                alert('Import failed: ' + (err.response?.data?.error || err.message));
                                            }
                                        }}
                                    />
                                </Button>
                            </Box>
                        </CardContent>
                    </Card>
                </Grid>

                {/* Apply Button */}
                <Grid item xs={12}>
                    <Button
                        fullWidth
                        variant="contained"
                        size="large"
                        onClick={handleApply}
                        disabled={updateMutation.isPending}
                        sx={{ bgcolor: '#f50057', color: '#fff', fontWeight: 'bold', py: 2, fontSize: '1.2rem', '&:hover': { bgcolor: '#c51162' } }}
                    >
                        {updateMutation.isPending ? 'APPLYING...' : 'APPLY ALL FIREWALL POLICIES'}
                    </Button>
                </Grid>
            </Grid>

            <Snackbar open={notification.open} autoHideDuration={6000} onClose={() => setNotification({ ...notification, open: false })}>
                <Alert onClose={() => setNotification({ ...notification, open: false })} severity="success" sx={{ width: '100%' }}>
                    {notification.message}
                </Alert>
            </Snackbar>
        </Box>
    );
}
