import '@fontsource/inter/400.css'
import '@fontsource/inter/700.css'

export default {
  breakpoints: [
    '40em', '56em', '64em',
  ],
  buttons: {
    primary: {
      color: 'background',
      bg: 'primary',
      cursor: 'pointer',
      fontFamily: 'body',
      '&:hover': {
        bg: 'secondary',
      },
    },
  },
  colors: {
    text: '#ffffff',
    background: '#00060C',
    primary: '#CFE4FF',
    secondary: '#AED1FE',
    accent: '#D67C78',
    highlight: '#FFDB78',
    muted: '#eeeeee',
    altBackground: '#0B1117',
    lightBackground: '#192128',
    navbar: '#000000',
  },
  fonts: {
    body: 'Inter, system-ui, sans-serif',
    heading: 'Inter, system-ui, sans-serif',
    monospace: 'Menlo, monospace',
  },
  fontSizes: [
    12, 14, 16, 20, 24, 32, 48, 64,
  ],
  fontWeights: {
    body: 400,
    heading: 700,
    bold: 700,
  },
  lineHeights: {
    body: 1.5,
    heading: 1.125,
  },
  sizes: {
    navbar: '90px',
    container: '50rem',
  },
  styles: {
    root: {
      fontFamily: 'body',
      fontWeight: 'body',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'stretch',
      scrollBehavior: 'smooth',
    },
    a: {
      color: 'text',
    },
  },
}
