// eslint-disable-next-line @typescript-eslint/no-require-imports
const path = require('path');

module.exports = {
  entry: {
    background: './src/background.ts',
    content:    './src/content.ts',
    popup:      './src/popup.ts',
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist'),
    clean: true,
  },
  // Service workers and content scripts cannot share a chunk,
  // so we disable code splitting entirely.
  optimization: {
    splitChunks: false,
    runtimeChunk: false,
  },
};
