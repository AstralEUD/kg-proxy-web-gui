import React, { useEffect, useRef, useState } from 'react';
import { Box, Typography, useTheme } from '@mui/material';
import createGlobe from 'cobe';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import { scaleLinear } from 'd3-scale';
import { Tooltip } from 'react-tooltip';

// 1. Service Pipe Visualization - Canvas Optimization (60FPS without React renders)
export const ServicePipe = ({ activeCount = 0, totalCount = 0, passedCount = 0 }) => {
    const canvasRef = useRef(null);
    const theme = useTheme();
    const particlesRef = useRef([]);

    useEffect(() => {
        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        let animationFrameId;

        const resize = () => {
            if (canvas.parentElement) {
                canvas.width = canvas.parentElement.offsetWidth;
                canvas.height = 120;
            }
        };
        window.addEventListener('resize', resize);
        resize();

        const render = () => {
            if (!canvas) return;
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // 1. Draw Background (Gradient Pipe)
            const gradient = ctx.createLinearGradient(0, 0, canvas.width, 0);
            gradient.addColorStop(0, '#1a1a1a');
            gradient.addColorStop(0.5, '#222');
            gradient.addColorStop(1, '#1a1a1a');
            ctx.fillStyle = gradient;
            ctx.fillRect(0, 24, canvas.width, 72); // Central pipe strip

            // Borders
            ctx.strokeStyle = '#444';
            ctx.beginPath();
            ctx.moveTo(0, 24); ctx.lineTo(canvas.width, 24);
            ctx.moveTo(0, 96); ctx.lineTo(canvas.width, 96);
            ctx.stroke();

            // 2. Spawn Particles based on simulated density
            if (Math.random() < 0.3) {
                particlesRef.current.push({
                    x: 0,
                    y: 24 + Math.random() * 72,
                    speed: 2 + Math.random() * 4,
                    color: Math.random() > 0.9 ? '#f50057' : '#00e5ff' // 10% blocked (red), 90% allowed (cyan)
                });
            }

            // 3. Move & Draw Particles
            particlesRef.current.forEach((p) => {
                p.x += p.speed;
                ctx.fillStyle = p.color;
                ctx.beginPath();
                ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
                ctx.fill();
            });

            // Remove off-screen particles
            particlesRef.current = particlesRef.current.filter(p => p.x < canvas.width);

            animationFrameId = requestAnimationFrame(render);
        };
        render();

        return () => {
            window.removeEventListener('resize', resize);
            cancelAnimationFrame(animationFrameId);
        };
    }, []);

    return (
        <Box sx={{ position: 'relative', height: 120, bgcolor: '#0a0a0a', borderRadius: 2, overflow: 'hidden', border: '1px solid #333', display: 'flex', alignItems: 'center' }}>
            <canvas ref={canvasRef} style={{ display: 'block', width: '100%', height: '100%' }} />

            {/* Incoming Stats (Left) */}
            <Box sx={{ position: 'absolute', left: 20, zIndex: 20, textAlign: 'left', textShadow: '0 2px 4px rgba(0,0,0,0.8)' }}>
                <Typography variant="caption" sx={{ color: '#888', display: 'block' }}>Incoming</Typography>
                <Typography variant="h5" sx={{ color: '#fff', fontWeight: 'bold' }}>{totalCount.toLocaleString()}</Typography>
            </Box>

            {/* Central Circle (Active) */}
            <Box sx={{
                position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%, -50%)',
                width: 80, height: 80, borderRadius: '50%',
                background: 'radial-gradient(circle, #2a2a2a 0%, #000 100%)',
                border: `2px solid ${theme.palette.primary.main}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                zIndex: 10, boxShadow: `0 0 20px ${theme.palette.primary.main}40`
            }}>
                <Typography variant="h5" sx={{ fontWeight: 'bold', color: '#fff' }}>{activeCount}</Typography>
            </Box>

            {/* Passed Stats (Right) */}
            <Box sx={{ position: 'absolute', right: 20, zIndex: 20, textAlign: 'right', textShadow: '0 2px 4px rgba(0,0,0,0.8)' }}>
                <Typography variant="caption" sx={{ color: '#00c853', display: 'block' }}>Passed</Typography>
                <Typography variant="h5" sx={{ color: '#00c853', fontWeight: 'bold' }}>{passedCount.toLocaleString()}</Typography>
            </Box>

            <Typography sx={{ position: 'absolute', bottom: 5, right: '50%', transform: 'translateX(50%)', fontSize: 10, color: '#666' }}>Active Requests</Typography>
        </Box>
    );
};

// 2. Latency Scatter Plot (Scanner Mode)
export const LatencyScatter = () => {
    const canvasRef = useRef(null);
    const theme = useTheme();

    useEffect(() => {
        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        let animationFrameId;
        let xPos = 0;

        const resize = () => {
            canvas.width = canvas.parentElement.offsetWidth;
            canvas.height = canvas.parentElement.offsetHeight;
            ctx.fillStyle = '#0a0a0a';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
        };
        window.addEventListener('resize', resize);
        resize();

        const render = () => {
            ctx.fillStyle = 'rgba(10, 10, 10, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.beginPath();
            ctx.moveTo(xPos, 0);
            ctx.lineTo(xPos, canvas.height);
            ctx.strokeStyle = 'rgba(0, 229, 255, 0.1)';
            ctx.lineWidth = 2;
            ctx.stroke();

            if (Math.random() > 0.3) {
                const y = Math.random() > 0.8 ? Math.random() * canvas.height * 0.4 : Math.random() * canvas.height * 0.2 + (canvas.height * 0.7);
                const size = Math.random() * 2 + 1;
                ctx.beginPath();
                ctx.arc(xPos, y, size, 0, Math.PI * 2);
                ctx.fillStyle = y < canvas.height * 0.5 ? '#f50057' : theme.palette.primary.main;
                ctx.fill();
            }

            xPos += 2;
            if (xPos > canvas.width) xPos = 0;

            animationFrameId = requestAnimationFrame(render);
        };
        render();

        return () => {
            window.removeEventListener('resize', resize);
            cancelAnimationFrame(animationFrameId);
        };
    }, []);

    return (
        <Box sx={{ width: '100%', height: '100%', position: 'relative', bgcolor: '#0a0a0a', overflow: 'hidden', borderRadius: 2, border: '1px solid #333' }}>
            <canvas ref={canvasRef} style={{ display: 'block' }} />
            <Typography sx={{ position: 'absolute', top: 10, left: 10, fontSize: 12, color: '#888' }}>Latency X-View (Scanner Mode)</Typography>
        </Box>
    );
};

// 3. 3D Globe Visualization (Cobe) - Kept for reference but not currently used in Traffic.jsx
export const Globe3D = () => {
    const canvasRef = useRef();

    useEffect(() => {
        let phi = 0;

        const globe = createGlobe(canvasRef.current, {
            devicePixelRatio: 2,
            width: 600,
            height: 600,
            phi: 0,
            theta: 0,
            dark: 1,
            diffuse: 1.2,
            mapSamples: 16000,
            mapBrightness: 6,
            baseColor: [0.1, 0.1, 0.1],
            markerColor: [0, 0.8, 1], // Cyan
            glowColor: [0.1, 0.1, 0.1],
            markers: [
                { location: [37.5665, 126.9780], size: 0.1 },
                { location: [40.7128, -74.0060], size: 0.05 },
                { location: [51.5074, -0.1278], size: 0.05 },
            ],
            onRender: (state) => {
                state.phi = phi;
                phi += 0.005;
            },
        });

        return () => {
            globe.destroy();
        };
    }, []);

    return (
        <Box sx={{ width: '100%', height: '100%', minHeight: 400, display: 'flex', justifyContent: 'center', alignItems: 'center', bgcolor: '#050505', overflow: 'hidden', position: 'relative' }}>
            <Box sx={{ width: '100%', height: '100%', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                <canvas
                    ref={canvasRef}
                    style={{ width: 600, height: 600, maxWidth: '100%', maxHeight: '100%', aspectRatio: '1', objectFit: 'contain' }}
                />
            </Box>
        </Box>
    );
};

// 4. 2D World Map (Flat) - With Tooltips
const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export const WorldMap2D = ({ data = [] }) => {
    return (
        <Box sx={{ width: '100%', height: '100%', minHeight: 400, bgcolor: '#050505', display: 'flex', justifyContent: 'center', alignItems: 'center', overflow: 'hidden' }}>
            <ComposableMap
                projection="geoMercator"
                projectionConfig={{
                    scale: 160,
                }}
                style={{ width: "100%", height: "100%" }}
            >
                <Geographies geography={geoUrl}>
                    {({ geographies }) =>
                        geographies.map((geo) => {
                            const countryName = geo.properties.name;
                            const countryStats = data.filter(d => d.countryName === countryName || d.countryCode === countryName);
                            const total = countryStats.length;
                            const passed = countryStats.filter(d => d.status === 'allowed').length;
                            const blocked = countryStats.filter(d => d.status === 'blocked').length;

                            const isBlocked = blocked > 0;
                            const isAllowed = passed > 0;

                            let fillColor = "#1a1a1a";
                            if (isBlocked) fillColor = "#f50057";
                            if (isAllowed && !isBlocked) fillColor = "#00e5ff";
                            if (isAllowed && isBlocked) fillColor = "#ffab00";
                            if (total === 0) fillColor = "#1a1a1a";

                            return (
                                <Geography
                                    key={geo.rsmKey}
                                    geography={geo}
                                    fill={fillColor}
                                    stroke="#333"
                                    strokeWidth={0.5}
                                    style={{
                                        default: { outline: "none" },
                                        hover: { fill: "#444", outline: "none" },
                                        pressed: { outline: "none" },
                                    }}
                                    data-tooltip-id="map-tooltip"
                                    data-tooltip-content={total > 0 ? `${countryName} | Passed: ${passed} | Blocked: ${blocked}` : `${countryName} (No Traffic)`}
                                />
                            );
                        })
                    }
                </Geographies>
            </ComposableMap>
            <Tooltip id="map-tooltip" style={{ backgroundColor: "#000", border: '1px solid #333', borderRadius: 4, fontSize: 12, zIndex: 100 }} />
        </Box>
    );
};
