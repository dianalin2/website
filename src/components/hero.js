/** @jsx jsx */
import { Box, jsx } from 'theme-ui'

const Hero = ({ children, big, ...props }) => (
  <Box
    {...props}
    sx={{
      p: '2rem',
      pt: theme => `calc(3rem + ${theme.space.navbar})`,
      backgroundColor: 'primary',
      minHeight: (big) ? '75vh' : '20rem',
      color: 'inverse',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center',
      alignItems: 'center',
      'h1': {
        fontSize: 6,
      },
      '& > *': {
        textAlign: 'center',
        maxWidth: 'container',
        width: '90%',
      },
    }}
  >
    {children}
  </Box>
)

export default Hero
