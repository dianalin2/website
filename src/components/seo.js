import React from 'react'
import { Helmet } from 'react-helmet'
import { useLocation } from '@reach/router'
import { useStaticQuery, graphql } from 'gatsby'

// TODO: make this different for every page?

const SEO = () => {
  const { pathname } = useLocation()
  const {
    site: {
      siteMetadata: {
        title,
        titleTemplate,
        description,
        url,
        image,
      },
    },
  } = useStaticQuery(query)

  return (
    <Helmet title={title} titleTemplate={titleTemplate}>
      <meta name='description' content={description} />
      <meta property='og:type' content='website' />
      <meta property='og:url' content={url + pathname} />
      <meta property='og:title' content={title} />
      <meta property='og:description' content={description} />
      <meta property='og:image' content={image} />
      <link rel='icon' type='image/x-icon' href='/csc/favicon.ico' />
    </Helmet>
  )
}

export default SEO

const query = graphql`
  query SEO {
    site {
      siteMetadata {
        description
        image
        title
        titleTemplate
        url
      }
    }
  }
`
