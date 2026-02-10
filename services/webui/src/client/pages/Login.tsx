import { useNavigate, useLocation } from 'react-router-dom';
import { LoginPageBuilder } from '@penguintechinc/react-libs';
import { useAuth } from '../hooks/useAuth';

interface LocationState {
  from?: { pathname: string };
}

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = (location.state as LocationState)?.from?.pathname || '/';

  const handleLoginSuccess = async (token: string) => {
    // Token is already set by LoginPageBuilder, just need to navigate
    // But we need to update our auth store
    // The LoginPageBuilder returns the access_token, but we need to fetch user data
    try {
      // Login function will handle setting tokens and fetching user
      // Since LoginPageBuilder already authenticated, we just need to sync state
      navigate(from, { replace: true });
    } catch (err) {
      console.error('Login success handler error:', err);
    }
  };

  const handleLoginSubmit = async (credentials: { email: string; password: string }) => {
    // Use our custom login function which updates Zustand store
    await login(credentials);
    navigate(from, { replace: true });
  };

  return (
    <LoginPageBuilder
      apiBaseUrl={import.meta.env.VITE_API_URL || '/api/v1'}
      onLoginSuccess={handleLoginSuccess}
      onLoginSubmit={handleLoginSubmit}
      appName="SkausWatch"
      appLogo="/logo.png"
      enableMFA={false}  // Can be enabled when backend supports it
      enableOAuth2={false}  // Can be enabled when backend supports it
      enableCaptcha={false}
      showCookieConsent={false}
      theme={{
        primaryColor: '#D4AF37',  // Gold color
        backgroundColor: '#0A0A0B',  // Dark background
        cardBackground: '#1A1A1F',
        textColor: '#E5E7EB',
        accentColor: '#D4AF37',
      }}
    />
  );
}
