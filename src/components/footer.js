/** @jsx jsx */
import { IoFlagSharp, IoLogoDiscord, IoLogoFacebook } from 'react-icons/io5'
import { Box, Grid, IconButton, jsx } from 'theme-ui'

const FooterIcon = ({Icon, href, ...props}) => (
  <IconButton
    {...props}
    as='a'
    href={href}
    target='_blank'
    rel='nofollow noopener noreferrer'
  >
    <Icon />
  </IconButton>
)

const Footer = (props) => (
  <Box
    {...props}
    sx={{
      bg: 'lightBackground',
      height: 72,
      display: 'flex',
      alignItems: 'center',
      px: ['2rem', '3rem', '4rem'],
    }}
  >
    <Grid
      columns={3}
      gap={[3, null, 4]}
      sx={{
        ml: 'auto',
      }}
    >
      <FooterIcon href='https://www.facebook.com/groups/tjcsc' Icon={IoLogoFacebook} />
      <FooterIcon href='https://ctf.tjcsec.club/' Icon={IoFlagSharp} />
      <FooterIcon href='https://tjcsec.club/discord' Icon={IoLogoDiscord} />
    </Grid>
  </Box>
)

export default Footer
