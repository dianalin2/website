/** @jsx jsx */
import { jsx } from 'theme-ui'

import Layout from '../components/layout'
import Hero from '../components/hero'
import Container from '../components/container'
import Link from '../components/link'

const Presentations = () => {
  return (
    <Layout>
      <Hero title='Presentations' />
      <Container>
        This is the presentations page
      </Container>
    </Layout>
  )
}

export default Presentations
