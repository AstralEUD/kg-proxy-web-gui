import React, { useState } from 'react';
import { Box, Typography, Card, CardContent, Grid, Switch, FormControlLabel, Button, Slider, Chip, Divider, TextField, IconButton, Alert, Snackbar } from '@mui/material';
import { Shield, Public, GppGood, Bolt, Add, Delete, CheckCircle } from '@mui/icons-material';
import client from '../api/client';

export default function Policy() {
    const [settings, setSettings] = useState({
        global_protection: true,
        block_vpn: false,
        block_tor: false,
        syn_cookies: true,
        protection_level: 2,
        geo_allow_countries: ['KR'], // Whitelist mode: Default allow Korea
        smart_banning: false,
        ebpf_enabled: false
    });

    // Custom IP Block List
    const [blockedIps, setBlockedIps] = useState(['45.33.22.11', '192.168.0.55']);
    const [newIp, setNewIp] = useState('');
    const [error, setError] = useState('');
    const [notification, setNotification] = useState({ open: false, message: '' });

    const allCountries = ["KR", "US", "CN", "JP", "DE", "RU", "BR", "GB", "CA", "AU", "IN", "FR", "ID", "VN"];

    const handleChange = (name) => (e) => {
        setSettings({ ...settings, [name]: e.target.checked });
    };

    const handleSlider = (name) => (e, val) => {
        setSettings({ ...settings, [name]: val });
    };

    const handleCountryToggle = (code) => {
        setSettings(prev => {
            const list = prev.geo_allow_countries.includes(code)
                ? prev.geo_allow_countries.filter(c => c !== code)
                : [...prev.geo_allow_countries, code];
            return { ...prev, geo_allow_countries: list };
        });
    };

    const validateIP = (ip) => {
        const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipv4Regex.test(ip);
    };

    const handleAddIp = () => {
        if (!newIp) return;

        if (!validateIP(newIp)) {
            setError('Invalid IP address format (e.g., 192.168.1.1)');
            return;
        }

        if (blockedIps.includes(newIp)) {
            setError('IP is already in the blacklist');
            return;
        }

        setBlockedIps([...blockedIps, newIp]);
        setNewIp('');
        setError('');
    };

    const handleDeleteIp = (ip) => {
        setBlockedIps(blockedIps.filter(i => i !== ip));
    };

    const handleApply = async () => {
        try {
            // Send to backend
            // Note: logic changed to 'geo_allow_countries' (Whitelist)
            await client.post('/firewall/apply', { ...settings, blocked_ips: blockedIps });
            setNotification({ open: true, message: 'Firewall policies applied successfully!' });
        } catch (e) {
            alert('Error applying policies');
        }
    };

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

                {/* 2. Geo Whitelisting (Allowed Countries) */}
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
                        </CardContent>
                    </Card>
                </Grid>

                {/* 3. Custom IP Blocking (Validated) */}
                <Grid item xs={12} md={6}>
                    <Card sx={{ bgcolor: '#111', border: '1px solid #222', height: '100%' }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#fff', mb: 2, display: 'flex', alignItems: 'center' }}>
                                <Shield sx={{ mr: 1, color: '#f50057' }} /> Custom IP Blacklist
                            </Typography>
                            <Box sx={{ display: 'flex', mb: 1 }}>
                                <TextField
                                    size="small"
                                    fullWidth
                                    placeholder="Enter IP Address (e.g. 1.2.3.4)"
                                    value={newIp}
                                    onChange={(e) => { setNewIp(e.target.value); setError(''); }}
                                    error={!!error}
                                    helperText={error}
                                    sx={{ mr: 1, bgcolor: '#0a0a0a', '& input': { color: '#fff' }, '& fieldset': { borderColor: '#333' } }}
                                />
                                <Button variant="contained" color="error" onClick={handleAddIp} startIcon={<Add />} sx={{ height: 40 }}>Block</Button>
                            </Box>
                            <Box sx={{ maxHeight: 150, overflow: 'auto', border: '1px solid #222', borderRadius: 1, p: 1 }}>
                                {blockedIps.map(ip => (
                                    <Box key={ip} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1, bgcolor: '#222', px: 1, borderRadius: 1 }}>
                                        <Typography variant="body2" sx={{ fontFamily: 'monospace', color: '#f50057' }}>{ip}</Typography>
                                        <IconButton size="small" onClick={() => handleDeleteIp(ip)}><Delete sx={{ fontSize: 16, color: '#666' }} /></IconButton>
                                    </Box>
                                ))}
                                {blockedIps.length === 0 && <Typography variant="caption" sx={{ color: '#666' }}>No custom blocked IPs.</Typography>}
                            </Box>
                        </CardContent>
                    </Card>
                </Grid>

                {/* 4. Next-Gen Tech */}
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
                        sx={{ bgcolor: '#f50057', color: '#fff', fontWeight: 'bold', py: 2, fontSize: '1.2rem', '&:hover': { bgcolor: '#c51162' } }}
                    >
                        APPLY ALL FIREWALL POLICIES
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
