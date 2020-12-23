/** @jsx jsx */
import { Heading, Box, Flex, jsx } from 'theme-ui'
import { useStaticQuery, graphql } from 'gatsby'

import Layout from '../components/layout'
import Hero from '../components/hero'

const Index = () => {
  const {
    site: {
      siteMetadata: {
        description,
      },
    },
  } = useStaticQuery(query)
  return (
    <Layout>
      <Hero big>
        <Heading as='h1' mb='2rem'>TJ Computer Security Club</Heading>
        <Heading as='h2'>{description}</Heading>
      </Hero>
      <Flex
        as='section'
        sx={{
          p: '2rem',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          '& > *': {
            textAlign: 'center',
            maxWidth: 'container',
            width: '90%',
          },
        }}
      >
        <Heading as='h1' sx={{ fontSize: 5 }}>Officers</Heading>
        <Box>
          pepega
        </Box>
      </Flex>
    </Layout>
  )
}

export default Index

const query = graphql`
  {
    site {
      siteMetadata {
        description
      }
    }
  }
`
