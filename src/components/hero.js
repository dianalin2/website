/** @jsx jsx */
import { Heading, jsx } from 'theme-ui'
import { motion } from 'framer-motion'

import Container from './container'
import { fadeInUp, stagger } from '../animations/animations'

const Hero = ({ title, subtitle, ...props }) => (
  <Container
    {...props}
    sx={{
      pt: (theme) => `calc(2rem + ${theme.sizes.navbar}px)`,
    }}
  >
    <motion.div variants={stagger()} animate='animate' initial='initial'>
      <motion.div variants={fadeInUp()}>
        <Heading as='h1' sx={{ fontSize: [5, 6, 7] }}>
          {title}
        </Heading>
      </motion.div>
      {subtitle && (
        <motion.div variants={fadeInUp({ duration: 0.22 })}>
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
        </motion.div>
      )}
    </motion.div>
  </Container>
)

export default Hero
