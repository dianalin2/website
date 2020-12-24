/** @jsx jsx */
import { Box, jsx } from 'theme-ui'

const Container = ({ children, ...props }) => (
  <Box
    {...props}
    sx={{
      py: '1rem',
      px: ['2rem', '3rem', '4rem'],
    }}
  >
    {children}
  </Box>
)

export default Container
