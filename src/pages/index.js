/** @jsx jsx */
import { Box, Button, Flex, Grid, Heading, Text, jsx } from 'theme-ui'
import { graphql } from 'gatsby'
import Img from 'gatsby-image'
import scrollTo from 'gatsby-plugin-smoothscroll'

import Layout from '../components/layout'
import Container from '../components/container'
import OfficerCard from '../components/officercard'

import CircuitBoard from '../images/circuit-board.svg'

const Index = ({ data }) => {
  const {
    site: {
      siteMetadata: {
        description,
      },
    },
    hero: {
      childImageSharp: {
        fluid: hero,
      },
    },
    club: {
      childImageSharp: {
        fluid: club,
      },
    },
    allAboutYaml: {
      edges: about,
    },
    allOfficersYaml: {
      edges: officers,
    },
  } = data
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
          <Img fluid={hero} alt='TJCSC at Lockheed Martin CYBERQUEST 2019'
            sx={{
              borderRadius: 4,
              mb: 1,
            }}
          />
          TJCSC at Lockheed Martin CYBERQUEST 2019
        </Flex>
      </Flex>
      <Flex id='about'
        sx={{
          bg: 'altBackground',
          '& > *': {
            flex: '1 1 0',
          },
        }}
      >
        <Flex
          sx={{
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
          }}
        >
          <Heading
            as='h1'
            sx={{
              m: [4, 5, 6],
              fontSize: [5, 6, 7],
            }}
          >
            The Club
          </Heading>
        </Flex>
        <Img fluid={{ ...club, aspectRatio: 1.778 }} alt='TJ Computer Security Club Meeting, October 2016'
          sx={{
            display: ['none', null, 'block'],
          }}
        />
      </Flex>
      <Grid
        columns={[1, null, 3]}
        gap={5}
        sx={{
          bg: 'lightBackground',
          p: [4, null, 5],
        }}
      >
        {about.map(({ node: { title, text } }, i) => (
          <Box key={i}>
            <Heading as='h2' mb={2}>{title}</Heading>
            <Text>{text}</Text>
          </Box>
        ))}
      </Grid>
      <Container my={4}>
        <Heading as='h1' mb={4}>Officers</Heading>
        <Grid
          sx={{
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          }}
        >
          {officers.map(({ node }, i) => (
            <OfficerCard
              key={i}
              data={node}
            />
          ))}
        </Grid>
      </Container>
    </Layout>
  )
}

export default Index

export const query = graphql`
  query Home {
    site {
      siteMetadata {
        description
      }
    }
    hero: file(relativePath: {eq: "cyberquest.png"}) {
      childImageSharp {
        fluid {
          ...GatsbyImageSharpFluid
        }
      }
    }
    club: file(relativePath: {eq: "evan.png"}) {
      childImageSharp {
        fluid {
          ...GatsbyImageSharpFluid
        }
      }
    }
    allAboutYaml {
      edges {
        node {
          title
          text
        }
      }
    }
    allOfficersYaml {
      edges {
        node {
          ...OfficerInfo
        }
      }
    }
  }
`
