const path = require('node:path');
const process = require('node:process');
const HtmlWebpackPlugin = require('html-webpack-plugin');

const isDevelopment = process.env.NODE_ENV !== 'production';

/** @param {boolean} useTypeScript */
const getSwcOptions = (useTypeScript) => /** @type {import('@swc/core').Options} */({
  jsc: {
    parser: useTypeScript
      ? { syntax: 'typescript', tsx: true }
      : { syntax: 'ecmascript', jsx: true },
    externalHelpers: true,
    transform: {
      react: {
        runtime: 'automatic',
        refresh: isDevelopment,
        development: isDevelopment,
      },
    },
  },
  env: {
    targets: 'defaults, chrome > 70, edge >= 79, firefox esr, safari >= 11, not dead, not ie > 0',
    mode: 'usage',
    coreJs: require('core-js/package.json').version,
  },
});

module.exports = /** @type {import('webpack').Configuration} */ ({
  mode: isDevelopment ? 'development' : 'production',
  entry: './src/index.tsx',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: isDevelopment ? '[name].js' : '[contenthash].js',
    hashFunction: 'xxhash64',
    hashDigestLength: 16,
    clean: true,
  },
  devtool: isDevelopment ? 'eval-source-map' : false,
  module: {
    rules: [
      {
        test: /\.[cm]?tsx?$/,
        exclude: /node_modules/,
        use: { loader: 'swc-loader', options: getSwcOptions(true) },
      },
      {
        test: /\.[cm]?jsx?$/,
        exclude: /node_modules/,
        use: { loader: 'swc-loader', options: getSwcOptions(false) },
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.jsx', '.json'],
  },
  plugins: [
    new HtmlWebpackPlugin({ template: './public/index.html' }),
    isDevelopment && (() => {
      const ReactRefreshWebpackPlugin = require('@pmmmwh/react-refresh-webpack-plugin');
      return new ReactRefreshWebpackPlugin();
    })(),
  ].filter(Boolean),
  optimization: isDevelopment ? {} : {
    splitChunks: {
      cacheGroups: {
        framework: {
          chunks: 'all',
          name: 'framework',
          test: /[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/,
          priority: 40,
          enforce: true,
        },
        vendors: {
          chunks: 'all',
          name: 'vendors',
          test: /[\\/]node_modules[\\/]/,
          priority: 20,
        },
      },
    },
    runtimeChunk: { name: 'webpack' },
  },
  cache: {
    type: 'filesystem',
    cacheDirectory: path.join(__dirname, 'node_modules', '.cache', 'webpack'),
  },
  devServer: {
    port: 8081,
    hot: true,
    historyApiFallback: true,
    proxy: [
      {
        context: ['/admin', '/health'],
        target: 'http://localhost:8787',
      },
    ],
  },
});
