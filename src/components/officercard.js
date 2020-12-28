/** @jsx jsx */
import { graphql } from 'gatsby'
import Img from 'gatsby-image'

import { Box, Heading, Text, jsx } from 'theme-ui'

const OfficerCard = ({ data, ...props }) => {
  const {
    name,
    position,
    avatar: {
      childImageSharp: {
        fluid: avatar,
      },
    },
  } = data
  return (
    <Box
      {...props}
      sx={{
        borderRadius: 12,
        bg: 'lightBackground',
        overflow: 'hidden',
      }}
    >
      <Img fluid={avatar} alt={name} />
      <Box
        p={3}
        sx={{
          textAlign: 'center',
        }}
      >
        <Heading as='h3'>{name}</Heading>
        <Text>{position}</Text>
      </Box>
    </Box>
  )
}

export default OfficerCard

export const query = graphql`
  fragment OfficerInfo on OfficersYaml {
    name
    position
    avatar {
      childImageSharp {
        fluid(maxHeight: 400, maxWidth: 400, traceSVG: { color: "#00060c" }) {
          ...GatsbyImageSharpFluid_tracedSVG
        }
      }
    }
  }
`
