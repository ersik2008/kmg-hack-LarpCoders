import React, { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;

    const verify = async (token: string) => {
      // A token in localStorage is not proof of a live session: it can be a
      // leftover from a revoked/expired login, or restored from the browser
      // history entry of the OAuth callback. Always confirm with the backend.
      try {
        const res = await fetch('http://localhost:3000/api/auth/me', {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (cancelled) return;

        if (res.ok) {
          setIsAuthenticated(true);
        } else {
          localStorage.removeItem('kmg_token');
          setIsAuthenticated(false);
        }
      } catch (err) {
        // Backend unreachable — do not silently treat the user as logged in.
        console.error('Session verification failed', err);
        if (!cancelled) setIsAuthenticated(false);
      }
    };

    // Check URL parameters for a token first (after GitHub callback)
    const queryParams = new URLSearchParams(location.search);
    const urlToken = queryParams.get('token');

    if (urlToken) {
      localStorage.setItem('kmg_token', urlToken);
      // Clean up the URL by removing the token
      navigate(location.pathname, { replace: true });
      verify(urlToken);
    } else {
      const storedToken = localStorage.getItem('kmg_token');
      if (!storedToken) {
        setIsAuthenticated(false);
      } else {
        verify(storedToken);
      }
    }

    return () => {
      cancelled = true;
    };
  }, [location, navigate]);

  if (isAuthenticated === null) {
    return <div>Loading...</div>; // Could be a sleek spinner
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

export default ProtectedRoute;
