import { useNavigate, useLocation } from 'react-router-dom';
import { LoginPageBuilder } from '@penguintechinc/react-libs';
import type { LoginResponse } from '@penguintechinc/react-libs';
import { useAuth } from '../hooks/useAuth';

interface LocationState {
  from?: { pathname: string };
}

export default function Login() {
  const { checkAuth } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = (location.state as LocationState)?.from?.pathname || '/';

  const handleSuccess = async (_response: LoginResponse) => {
    // LoginPageBuilder POSTs to api.loginUrl itself; the manager's response
    // already set the HttpOnly sw_access/sw_refresh + sw_csrf cookies, so
    // there is nothing to store here. Hydrate auth state from the new
    // cookie session via /auth/me rather than trusting response body
    // fields (which never carry the token client-side, H2 audit fix).
    console.log('[Login] Login succeeded');
    await checkAuth();
    navigate(from, { replace: true });
  };

  const handleError = (error: Error) => {
    console.error('[Login] Login failed', error.message);
  };

  return (
    <LoginPageBuilder
      api={{ loginUrl: '/api/v1/auth/login' }}
      branding={{ appName: 'SkausWatch' }}
      onSuccess={handleSuccess}
      onError={handleError}
      showForgotPassword={false}
      showSignUp={false}
    />
  );
}
