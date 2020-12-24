import React from 'react'
import { Helmet } from 'react-helmet'
import { useLocation } from '@reach/router'
import { useStaticQuery, graphql, withPrefix, } from 'gatsby'

const SEO = (props) => {
  const { pathname } = useLocation()
  const {
    site: {
      siteMetadata: {
        title,
        description,
        url,
      },
    },
  } = useStaticQuery(query)

  return (
    <Helmet title={title} {...props}>
      <meta name='description' content={description} />
      <meta property='og:type' content='website' />
      <meta property='og:url' content={url + pathname} />
      <meta property='og:title' content={title} />
      <meta property='og:description' content={description} />
      <meta property='og:image' content={withPrefix('/meta.png')} />
      <link rel='icon' type='image/x-icon' href={withPrefix('/favicon.ico')} />
    </Helmet>
  )
}

export default SEO

const query = graphql`
  query SEO {
    site {
      siteMetadata {
        description
        title
        url
      }
    }
  }
`
