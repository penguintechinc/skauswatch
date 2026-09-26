// Flat config for ESLint 9 (replaces the deprecated .eslintrc.cjs, which
// referenced @typescript-eslint + react-refresh plugins that were never
// installed — lint was broken at HEAD). typescript-eslint 8.x is the
// ESLint-9-compatible line; no-explicit-any / no-unused-vars stay "warn"
// to preserve the base app's original intent (warnings do not fail CI).
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import jsxA11y from 'eslint-plugin-jsx-a11y';

// jsx-a11y bootstrap (release-audit #152): webui had zero a11y lint tooling
// and only 1/66 tsx files used ARIA. jsx-a11y's `recommended` config ships
// its ~30 rules at "error" severity; the codebase has never been linted for
// this, so flipping them straight to error would fail every build. Instead
// every jsx-a11y rule is downgraded to "warn" here so the tooling is live
// and every violation surfaces in `npm run lint` output without breaking
// the gate (`eslint src` has no --max-warnings, so warnings never fail CI).
// Full remediation of existing violations is tracked as a separate,
// dedicated a11y effort — this slice is tooling-only, per audit finding.
const jsxA11yWarnRules = Object.fromEntries(
  Object.entries(jsxA11y.flatConfigs.recommended.rules).map(([rule, config]) => {
    if (Array.isArray(config)) {
      return [rule, ['warn', ...config.slice(1)]];
    }
    return [rule, config === 'off' ? 'off' : 'warn'];
  }),
);

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'eslint.config.js'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'module',
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
      'jsx-a11y': jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11yWarnRules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
      // Pre-existing empty extension-interfaces across the base app's type
      // files; stylistic, downgraded to warn (tracked for batch-2 cleanup).
      '@typescript-eslint/no-empty-object-type': 'warn',
    },
  },
);
