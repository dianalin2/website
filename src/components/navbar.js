/** @jsx jsx */
import { Flex, jsx } from 'theme-ui'
import { useState } from 'react'
import Headroom from 'react-headroom'
import Hamburger from 'react-hamburger-menu'
import { graphql, useStaticQuery } from 'gatsby'

import Link from './link'

const NavLink = ({ children, ...props }) => (
  <Link
    {...props}
    sx={{
      textDecoration: 'none',
      color: 'text',
      fontSize: 3,
      '::after': {
        position: 'relative',
        display: 'block',
        width: '100%',
        top: '0.2em',
        height: 1,
        content: '""',
        bg: 'text',
        transition: '.2s',
        transform: 'scaleX(0)',
        transformOrigin: 'left center',
      },
      '&.active::after, :hover::after, :focus::after': {
        transform: 'scaleX(1)',
      },
      '&.active::after': {
        bg: 'primary',
      },
    }}
  >{children}</Link>
)

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false)
  const {
    site: {
      siteMetadata: {
        title,
        menuLinks,
      },
    },
  } = useStaticQuery(query)

  return (
    <Headroom
      disableInlineStyles
      className={isOpen ? 'open' : ''}
      sx={{
        position: 'fixed',
        width: '100%',
        zIndex: 999,
        '& > .headroom': {
          py: '2rem',
          px: ['2rem', '3rem', '4rem'],
          display: 'flex',
          justifyContent: 'space-between',
          transition: '0.2s linear',
          backgroundColor: isOpen ? 'navbar' : 'transparent',
          '&::before': {
            position: 'absolute',
            display: 'block',
            content: '""',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            zIndex: -999,
            backgroundColor: 'navbar',
            opacity: 1,
            transition: '0.2s linear',
          },
        },
        '& > .headroom--unfixed': {
          '&::before': {
            opacity: 0,
          },
        },
        '& > .headroom--scrolled': {
          transform: 'translateY(0)',
        },
        '& > .headroom--unpinned': {
          transform: 'translateY(-100%)',
        },
        '&.open > .headroom': {
          transform: 'translateY(0)',
        },
      }}
    >
      <NavLink to='/' sx={{ fontWeight: 'bold' }}>{title}</NavLink>
      <Hamburger
        isOpen={isOpen}
        menuClicked={() => setIsOpen(!isOpen)}
        width={18}
        height={15}
        strokeWidth={2}
        animationDuration={0.2}
        color='#ffffff'
        sx={{
          display: ['block', null, 'none'],
          cursor: 'pointer',
        }}
      />
      <Flex
        sx={{
          '@media (max-width: 56em)': {
            flexDirection: 'column',
            alignItems: 'flex-start',
            position: 'absolute',
            left: 0,
            top: '100%',
            width: '100%',
            backgroundColor: 'navbar',
            p: '2rem',
            pt: 0,
            opacity: isOpen ? 1 : 0,
            visibility: isOpen ? 'visible' : 'hidden',
            transition: '0.2s linear',
          },
        }}
      >
        {menuLinks.map(({ name, link }) => (
          <NavLink
            key={name}
            to={link}
            activeClassName={'active'}
            partiallyActive={true}
            sx={{
              ml: [0, null, '2rem'],
              p: ['0.5rem', null, 0],
            }}
          >
            {name}
          </NavLink>
        ))}
      </Flex>
    </Headroom>
  )
}

export default Navbar

const query = graphql`
  query Navbar {
    site {
      siteMetadata {
        title
        menuLinks {
          link
          name
        }
      }
    }
  }
`
