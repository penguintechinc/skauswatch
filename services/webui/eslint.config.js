// Flat config for ESLint 9 (replaces the deprecated .eslintrc.cjs, which
// referenced @typescript-eslint + react-refresh plugins that were never
// installed — lint was broken at HEAD). typescript-eslint 8.x is the
// ESLint-9-compatible line; no-explicit-any / no-unused-vars stay "warn"
// to preserve the base app's original intent (warnings do not fail CI).
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';

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
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
      // Pre-existing empty extension-interfaces across the base app's type
      // files; stylistic, downgraded to warn (tracked for batch-2 cleanup).
      '@typescript-eslint/no-empty-object-type': 'warn',
    },
  },
);
