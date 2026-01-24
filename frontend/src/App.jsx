import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Origins from './pages/Origins';
import Services from './pages/Services';
import Policy from './pages/Policy';
import Traffic from './pages/Traffic';
import Users from './pages/Users';
import SecurityRules from './pages/SecurityRules';
import ActiveBlocks from './pages/ActiveBlocks';
import CountryGroups from './pages/CountryGroups';
import NetworkTools from './pages/NetworkTools';
import AttackHistory from './pages/AttackHistory';
import Login from './pages/Login';
import { isAuthenticated } from './api/client';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00e5ff',
    },
    background: {
      default: '#0a0a0a',
      paper: '#1a1a1a',
    },
  },
  typography: {
    fontFamily: 'Roboto, sans-serif',
  },
});

const queryClient = new QueryClient();

// Protected Route component
function RequireAuth({ children }) {
  const location = useLocation();

  if (!isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route
              path="/"
              element={
                <RequireAuth>
                  <Layout />
                </RequireAuth>
              }
            >
              <Route index element={<Dashboard />} />
              <Route path="origins" element={<Origins />} />
              <Route path="services" element={<Services />} />
              <Route path="traffic" element={<Traffic />} />
              <Route path="policy" element={<Policy />} />
              <Route path="security/rules" element={<SecurityRules />} />
              <Route path="security/blocks" element={<ActiveBlocks />} />
              <Route path="security/groups" element={<CountryGroups />} />
              <Route path="tools/network" element={<NetworkTools />} />
              <Route path="attacks" element={<AttackHistory />} />
              <Route path="users" element={<Users />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
