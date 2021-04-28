import React from 'react'
import { Helmet } from 'react-helmet'
import { useLocation } from '@reach/router'
import { useStaticQuery, graphql, withPrefix } from 'gatsby'

const SEO = ({ title, description, ...props }) => {
  const { pathname } = useLocation()
  const {
    site: {
      siteMetadata: {
        title: defaultTitle,
        titleTemplate,
        description: defaultDescription,
        url,
      },
    },
  } = useStaticQuery(query)

  const data = {
    url: url + pathname,
    title: title ?? defaultTitle,
    description: description ?? defaultDescription,
  }

  const helmet = {
    title: data.title,
  }
  if (title) helmet.titleTemplate = titleTemplate

  return (
    <Helmet {...helmet} {...props}>
      <meta name='description' content={data.description} />
      <meta property='og:type' content='website' />
      <meta property='og:url' content={data.url} />
      <meta property='og:title' content={title} />
      <meta property='og:description' content={data.description} />
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
        titleTemplate
        url
      }
    }
  }
`
