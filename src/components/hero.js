/** @jsx jsx */
import { Heading, jsx } from 'theme-ui'

import Container from './container'

const Hero = ({ title, subtitle, ...props }) => (
  <Container
    {...props}
    sx={{
      pt: theme => `calc(2rem + ${theme.sizes.navbar})`,
    }}
  >
    <Heading as='h1' sx={{ fontSize: [5, 6, 7] }}>{title}</Heading>
    {subtitle &&
      <Heading
        as='h2'
        sx={{
          fontSize: [2, 3, 4],
          color: 'primary',
          mt: 3,
        }}
      >
        {subtitle}
      </Heading>
    }
  </Container>
)

export default Hero
