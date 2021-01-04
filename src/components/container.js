/** @jsx jsx */
import { Box, jsx } from 'theme-ui'

const Container = ({ children, ...props }) => (
  <Box
    {...props}
    sx={{
      py: '1rem',
      px: ['2rem', '3rem', '4rem'],
      width: '100%',
      maxWidth: 'container',
      mx: 'auto',
    }}
  >
    {children}
  </Box>
)

export default Container
