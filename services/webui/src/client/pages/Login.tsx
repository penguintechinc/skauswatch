import { LoginPageBuilder } from '@penguintechinc/react-libs';

export default function Login() {
  return (
    // @ts-expect-error - LoginPageBuilder types require props but defaults are available in context
    <LoginPageBuilder />
  );
}
