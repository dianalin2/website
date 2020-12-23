import 'fontsource-open-sans/400.css'
import 'fontsource-open-sans/700.css'

export default {
  breakpoints: [
    '40em', '56em', '64em',
  ],
  colors: {
    text: '#5a5a5a',
    background: '#ffffff',
    primary: '#008bff',
    secondary: '#23527c',
    accent: '#ffffff',
    highlight: '#b7b7fe',
    muted: '#eeeeee',
    inverse: '#ffffff',
  },
  fonts: {
    body: 'Open Sans, system-ui, sans-serif',
    heading: 'Open Sans, system-ui, sans-serif',
    monospace: 'Menlo, monospace',
  },
  fontSizes: [
    12, 14, 16, 20, 24, 32, 48, 64,
  ],
  fontWeights: {
    body: 400,
    heading: 400,
    bold: 700,
  },
  lineHeights: {
    body: 1.5,
    heading: 1.125,
  },
  styles: {
    root: {
      fontFamily: 'body',
      fontWeight: 'body',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'stretch',
    },
  },
  space: {
    navbar: '4rem',
  },
  sizes: {
    container: '50rem',
  },
}
