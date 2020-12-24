/** @jsx jsx */
import { jsx } from 'theme-ui'

import Layout from '../components/layout'
import Hero from '../components/hero'
import Container from '../components/container'
import Link from '../components/link'

const NotFoundPage = () => {
  return (
    <Layout>
      <Hero title='Page not found' />
      <Container>
        <p>
          Sorry{' '}
          <span role='img' aria-label='Pensive emoji'>
            😔
          </span>{' '}
          we couldn't find what you were looking for.
        </p>
        <Link to='/'>Go home</Link>
      </Container>
    </Layout>
  )
}

export default NotFoundPage
