import { useNavigate } from 'react-router-dom';
import { LoginPageBuilder } from '@penguintechinc/react-libs';
import type { LoginResponse } from '@penguintechinc/react-libs';
import { useAuth } from '../context/AuthContext.tsx';
import type { AuthUser } from '../types/icebox.ts';

export default function LoginPage() {
  const navigate = useNavigate();
  const { login } = useAuth();

  const handleSuccess = (response: LoginResponse) => {
    if (response.token && response.user) {
      login(response.token, response.user as unknown as AuthUser);
      navigate('/vault');
    }
  };

  return (
    <LoginPageBuilder
      api={{ loginUrl: '/api/v1/auth/login' }}
      branding={{
        appName: 'IceBox',
        tagline: 'Secure Secrets Vault',
        githubRepo: 'penguintechinc/skauswatch',
      }}
      onSuccess={handleSuccess}
      gdpr={{ enabled: true, privacyPolicyUrl: '/privacy' }}
      captcha={{
        enabled: true,
        provider: 'altcha',
        challengeUrl: '/api/v1/captcha/challenge',
        failedAttemptsThreshold: 3,
      }}
      mfa={{ enabled: true, codeLength: 6, allowRememberDevice: false }}
    />
  );
}
