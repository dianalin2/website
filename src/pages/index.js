/** @jsx jsx */
import { Box, Button, Flex, Grid, Heading, jsx } from 'theme-ui'
import { useStaticQuery, graphql } from 'gatsby'
import Img from 'gatsby-image'
import scrollTo from 'gatsby-plugin-smoothscroll'

import Layout from '../components/layout'
import Container from '../components/container'

import CircuitBoard from '../images/circuit-board.svg'

const Index = () => {
  const {
    site: {
      siteMetadata: {
        description,
      },
    },
    file: {
      childImageSharp: {
        fluid: image,
      },
    },
  } = useStaticQuery(query)
  return (
    <Layout>
      <Flex
        sx={{
          flexDirection: 'row',
          alignItems: 'stretch',
          justifyContent: 'center',
          minHeight: '100vh',
          '& > *': {
            flex: '1',
            pt: theme => theme.sizes.navbar,
            pb: '0.5rem',
            px: ['2rem', '3rem', '4rem'],
          },
        }}
      >
        <Flex
          sx={{
            bg: ['altBackground', null, 'background'],
            backgroundImage: [`url(${CircuitBoard})`, null, 'none'],
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'flex-start',
          }}
        >
          <Grid
            gap={[2, 3, 4]}
            sx={{
              justifyItems: 'start',
            }}
          >
            <Heading
              as='h1'
              sx={{
                fontSize: [5, 6, 7],
              }}
            >
              TJHSST Computer Security Club
            </Heading>
            <Heading
              as='h2'
              sx={{
                color: 'primary',
                fontSize: [2, 3, 4],
              }}
            >
              {description}
            </Heading>
            <Button onClick={() => scrollTo('#about')}>Learn More</Button>
          </Grid>
        </Flex>
        <Flex
          sx={{
            display: ['none', null, 'flex'],
            flex: '1',
            bg: 'altBackground',
            backgroundImage: `url(${CircuitBoard})`,
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'stretch',
          }}
        >
          <Box>
            <Img fluid={image} alt='TJCSC at Lockheed Martin CYBERQUEST 2019'
              sx={{
                borderRadius: 4,
                mb: 1,
              }}
            />
            TJCSC at Lockheed Martin CYBERQUEST 2019
          </Box>
        </Flex>
      </Flex>
      <Container id='about'>
        <Heading as='h1'>
          About
        </Heading>
      </Container>
    </Layout>
  )
}

export default Index

const query = graphql`
  query Home {
    site {
      siteMetadata {
        description
      }
    }
    file(relativePath: {eq: "cyberquest.png"}) {
      childImageSharp {
        fluid {
          ...GatsbyImageSharpFluid
        }
      }
    }
  }
`
