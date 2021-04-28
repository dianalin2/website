import '@fontsource/inter/400.css'
import '@fontsource/inter/700.css'

import { prismColors } from './prism'

export default {
  breakpoints: ['40em', '56em', '64em'],
  buttons: {
    primary: {
      color: 'background',
      bg: 'primary',
      cursor: 'pointer',
      fontFamily: 'body',
      '&:hover': {
        filter: 'brightness(0.9)',
      },
    },
    secondary: {
      color: 'background',
      bg: 'secondary',
      cursor: 'pointer',
      fontFamily: 'body',
      '&:hover': {
        filter: 'brightness(0.9)',
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
    gray: '#CCCCCC',
    altBackground: '#0B1117',
    lightBackground: '#192128',
    navbar: '#000000',
  },
  fonts: {
    body: 'Inter, system-ui, sans-serif',
    heading: 'Inter, system-ui, sans-serif',
    monospace: 'Menlo, monospace',
  },
  fontSizes: [12, 14, 16, 20, 24, 32, 48, 64],
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
    navbar: 90,
    container: 2000,
    writeup: 1000,
    footer: 72,
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
    a: {
      color: 'text',
      wordBreak: 'break-word',
      '&:hover': {
        filter: 'brightness(0.9)',
      },
    },
    code: {
      ...prismColors,
    },
  },
}
