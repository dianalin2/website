/** @jsx jsx */
import { Heading, jsx } from 'theme-ui'

import Container from './container'

const Hero = ({ title, ...props }) => (
  <Container
    {...props}
    sx={{
      pt: theme => `calc(2rem + ${theme.sizes.navbar})`,
    }}
  >
    <Heading as='h1' sx={{ fontSize: 6 }}>{title}</Heading>
  </Container>
)

export default Hero
